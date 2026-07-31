package objfile

import (
	"debug/gosym"
	"fmt"
)

// Wasm function "addresses" are indices in the module's function index
// space (imports first, then defined functions): wasm code has no
// virtual addresses, and call instructions target functions by index.
// Func.Addr holds that index and Func.Size the body size in bytes.

// wasmSection ids used by the loader.
const (
	wasmSecCustom = 0
	wasmSecImport = 2
	wasmSecMemory = 5
	wasmSecCode   = 10
	wasmSecData   = 11
)

// wasmSeg is one active data segment: init is copied to linear-memory
// offset off at instantiation.
type wasmSeg struct {
	off  int64
	init []byte
}

// openWasm loads a WebAssembly module. Function bodies come from the
// code section; names come from the embedded Go pclntab when present
// (exact symbol names) and otherwise from the name section, whose
// names the Go linker sanitizes (for example "internal/abi.(*Type)"
// becomes "internal_abi.__Type_").
func openWasm(data []byte) (*Binary, error) {
	var (
		importNames []string    // imported functions, in index order
		bodies      [][2]uint64 // [offset, size] of each code entry body
		nameSec     = map[uint64]string{}
		segs        []wasmSeg
		memPages    uint64 // initial size of memory 0, in 64KiB pages
	)

	c := &wasmCursor{data: data, pos: 8}
	for c.pos < len(data) && !c.fail {
		id := c.byte()
		size := c.uint()
		base := c.pos
		payload := c.bytes(size)
		if c.fail {
			return nil, fmt.Errorf("truncated wasm section %d", id)
		}
		sec := &wasmCursor{data: payload}
		switch id {
		case wasmSecCustom:
			if sec.name() == "name" {
				parseWasmNames(sec, nameSec)
			}
		case wasmSecImport:
			importNames = parseWasmImports(sec)
		case wasmSecMemory:
			if sec.uint() > 0 {
				flags := sec.byte()
				if pages := sec.uint(); !sec.fail && flags&4 == 0 {
					memPages = pages
				}
			}
		case wasmSecCode:
			for range sec.uint() {
				n := sec.uint()
				start := base + sec.pos
				sec.bytes(n)
				if sec.fail {
					// Check inside the loop: the declared count is
					// attacker-controlled and reads past the end are
					// no-ops, so an unchecked loop would spin on a
					// huge count in a tiny section.
					return nil, fmt.Errorf("malformed wasm code section")
				}
				bodies = append(bodies, [2]uint64{uint64(start), n})
			}
		case wasmSecData:
			segs = parseWasmData(sec)
		}
	}
	if c.fail {
		return nil, fmt.Errorf("malformed wasm module")
	}

	importCount := len(importNames)
	names := make([]string, importCount+len(bodies))
	copy(names, importNames)
	for i := range bodies {
		names[importCount+i] = nameSec[uint64(importCount+i)]
	}
	if goNames := wasmGoNames(segs, len(bodies)); goNames != nil {
		copy(names[importCount:], goNames)
	}

	bin := &Binary{Arch: ArchWasm, Funcs: map[string]*Func{}, wasmNames: names}
	for i, b := range bodies {
		name := names[importCount+i]
		if name == "" {
			name = fmt.Sprintf("func%d", importCount+i)
		}
		bin.Funcs[name] = &Func{
			Name: name,
			Addr: uint64(importCount + i),
			Size: b[1],
			code: data[b[0] : b[0]+b[1]],
			bin:  bin,
		}
	}

	// One range from the start of initialized data to the end of the
	// initial memory, for recognizing address-valued constants: global
	// data, including bss past the initialized segments, lives there
	// and its layout shifts freely between builds. An ordinary large
	// constant inside the range is masked too — inherent ambiguity of
	// wasm's flat low address space.
	var lo, hi int64
	for _, s := range segs {
		if lo == 0 || s.off < lo {
			lo = s.off
		}
		if end := s.off + int64(len(s.init)); end > hi {
			hi = end
		}
	}
	if memPages > 65536 {
		memPages = 65536 // wasm spec maximum; also keeps the multiply below in range
	}
	if memEnd := int64(memPages) * 64 * 1024; memEnd > hi {
		hi = memEnd
	}
	if lo < hi {
		bin.addRange(uint64(lo), uint64(hi-lo))
	}
	// Go wasm PCs encode a function as wasmPCBase plus its position in
	// the code section, shifted left by 16, with a block index in the
	// low bits. Function bodies materialize such PCs as i64.const
	// immediates (resumption points, function values); covering the PC
	// space lets normalization mask them like any other address, since
	// they shift whenever the function layout changes.
	bin.addRange(wasmPCBase<<16, uint64(len(bodies))<<16)
	return bin, nil
}

// wasmPCBase is the first function "address" the Go linker assigns on
// wasm (funcValueOffset in cmd/link).
const wasmPCBase = 0x1000

// parseWasmImports returns the names of imported functions as
// "module.field", in function index order. Non-function imports are
// skipped over.
func parseWasmImports(sec *wasmCursor) []string {
	var names []string
	for range sec.uint() {
		module := sec.name()
		field := sec.name()
		switch sec.byte() {
		case 0x00: // function
			sec.uint()
			names = append(names, module+"."+field)
		case 0x01: // table
			sec.byte()
			sec.skipLimits()
		case 0x02: // memory
			sec.skipLimits()
		case 0x03: // global
			sec.byte()
			sec.byte()
		case 0x04: // tag
			sec.byte()
			sec.uint()
		default:
			sec.fail = true
		}
		if sec.fail {
			return nil
		}
	}
	return names
}

// parseWasmNames fills out with the function-names subsection of the
// standard "name" custom section, keyed by function index.
func parseWasmNames(sec *wasmCursor, out map[uint64]string) {
	for sec.pos < len(sec.data) && !sec.fail {
		id := sec.byte()
		sub := &wasmCursor{data: sec.bytes(sec.uint())}
		if id != 1 { // function names
			continue
		}
		for range sub.uint() {
			idx := sub.uint()
			name := sub.name()
			if sub.fail {
				break // huge declared count in a tiny subsection
			}
			out[idx] = name
		}
	}
}

// parseWasmData returns the active data segments with constant
// offsets. Parsing stops at the first unsupported form; the segments
// only feed pclntab recovery and address recognition, both of which
// degrade gracefully.
func parseWasmData(sec *wasmCursor) []wasmSeg {
	var segs []wasmSeg
	for range sec.uint() {
		flags := sec.uint()
		switch flags {
		case 1: // passive
			sec.bytes(sec.uint())
			continue
		case 0, 2: // active
			if flags == 2 {
				sec.uint() // memory index
			}
		default:
			return segs
		}
		var off int64
		switch sec.byte() {
		case 0x41: // i32.const
			off = sec.sint()
		case 0x42: // i64.const
			off = sec.sint()
		default:
			return segs
		}
		if sec.byte() != 0x0b { // end
			return segs
		}
		init := sec.bytes(sec.uint())
		if sec.fail || off < 0 {
			return segs
		}
		segs = append(segs, wasmSeg{off: off, init: init})
	}
	return segs
}

// wasmMaxImage caps the reconstructed linear-memory image used for
// pclntab recovery.
const wasmMaxImage = 1 << 31

// wasmGoNames recovers the exact Go symbol names of the defined
// functions from the pclntab embedded in the data segments. On wasm a
// function's pclntab entry PC is its position in code-section order,
// so the i-th table entry names the i-th defined function; a count
// mismatch means the layout assumption does not hold and the name
// section is used instead.
func wasmGoNames(segs []wasmSeg, nfuncs int) []string {
	var end, total int64
	for _, s := range segs {
		if e := s.off + int64(len(s.init)); e > end {
			end = e
		}
		total += int64(len(s.init))
	}
	// Bound the image by the data actually present: a hostile module
	// can place a tiny segment at a huge offset, and allocating up to
	// wasmMaxImage from a few bytes of input is an OOM vector. Real Go
	// binaries lay segments out compactly, so a generous slack over the
	// total initialized size is safe.
	if end <= 0 || end > wasmMaxImage || end > total+1<<20 || nfuncs == 0 {
		return nil
	}
	mem := make([]byte, end)
	for _, s := range segs {
		copy(mem[s.off:], s.init)
	}
	tab := findPclntab(mem)
	if tab == nil {
		return nil
	}
	st, err := gosym.NewTable(nil, gosym.NewLineTable(tab, 0))
	if err != nil || len(st.Funcs) != nfuncs {
		return nil
	}
	names := make([]string, nfuncs)
	for i, fn := range st.Funcs {
		names[i] = fn.Name
	}
	return names
}

// wasmCursor reads LEB128-encoded wasm structures. Reads past the end
// or over-long encodings set fail and return zeros, so callers check
// fail once instead of handling an error per read.
type wasmCursor struct {
	data []byte
	pos  int
	fail bool
}

// byte reads one byte.
func (c *wasmCursor) byte() byte {
	if c.pos >= len(c.data) {
		c.fail = true
		return 0
	}
	b := c.data[c.pos]
	c.pos++
	return b
}

// uint reads an unsigned LEB128.
func (c *wasmCursor) uint() uint64 {
	var v uint64
	for shift := 0; shift < 64; shift += 7 {
		b := c.byte()
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v
		}
	}
	c.fail = true
	return 0
}

// sint reads a signed LEB128.
func (c *wasmCursor) sint() int64 {
	var v int64
	for shift := 0; shift < 64; shift += 7 {
		b := c.byte()
		v |= int64(b&0x7f) << shift
		if b&0x80 == 0 {
			if b&0x40 != 0 && shift+7 < 64 {
				v |= -1 << (shift + 7) // sign-extend
			}
			return v
		}
	}
	c.fail = true
	return 0
}

// bytes reads n bytes as a slice into the underlying data.
func (c *wasmCursor) bytes(n uint64) []byte {
	if n > uint64(len(c.data)-c.pos) {
		c.fail = true
		return nil
	}
	b := c.data[c.pos : c.pos+int(n)]
	c.pos += int(n)
	return b
}

// name reads a length-prefixed UTF-8 name.
func (c *wasmCursor) name() string {
	return string(c.bytes(c.uint()))
}

// skipLimits skips a limits structure: flags, min, optional max.
func (c *wasmCursor) skipLimits() {
	flags := c.byte()
	c.uint()
	if flags&1 != 0 {
		c.uint()
	}
}
