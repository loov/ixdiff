// Package objfile loads executable binaries into a format-independent
// representation: the machine architecture and the set of functions
// with their addresses, sizes, and machine code.
package objfile

import (
	"bytes"
	"cmp"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
)

// Arch identifies the instruction set of a binary.
type Arch int

// Supported architectures. ArchUnknown is the invalid zero value.
const (
	ArchUnknown Arch = iota
	ArchAMD64
	ArchARM64
	Arch386
	ArchS390X
	ArchPPC64   // big-endian
	ArchPPC64LE // little-endian
	ArchRISCV64
	ArchLoong64
	ArchARM
	ArchWasm
)

// String returns the Go name of the architecture.
func (a Arch) String() string {
	switch a {
	case ArchAMD64:
		return "amd64"
	case ArchARM64:
		return "arm64"
	case Arch386:
		return "386"
	case ArchS390X:
		return "s390x"
	case ArchPPC64:
		return "ppc64"
	case ArchPPC64LE:
		return "ppc64le"
	case ArchRISCV64:
		return "riscv64"
	case ArchLoong64:
		return "loong64"
	case ArchARM:
		return "arm"
	case ArchWasm:
		return "wasm"
	default:
		return "unknown"
	}
}

// Binary is a loaded executable, backed by a read-only memory mapping
// of the file. Close releases the mapping; Func.Code slices become
// invalid afterwards.
type Binary struct {
	Arch Arch
	// Funcs maps symbol name to function.
	Funcs map[string]*Func
	// NoLayout reports that function addresses are deterministic
	// pseudo-addresses (file offsets in a Go compile archive) rather
	// than a memory layout: gaps between functions are not padding.
	NoLayout bool
	// ranges are the [start, end) virtual address ranges of the
	// binary's loadable sections, used to recognize address-valued
	// immediates.
	ranges [][2]uint64
	// dataSyms are the non-function symbols, sorted by address, used
	// to resolve data references to names.
	dataSyms []dataSym

	// text is the executable text section, a slice into the mapping,
	// starting at virtual address textAddr.
	text     []byte
	textAddr uint64

	// wasmNames maps the wasm function index space (imports first,
	// then defined functions) to names; nil for non-wasm binaries.
	wasmNames []string

	// closeMapping releases the file mapping.
	closeMapping func() error
}

// Close releases the binary's file mapping.
func (b *Binary) Close() error {
	if b.closeMapping == nil {
		return nil
	}
	err := b.closeMapping()
	b.closeMapping = nil
	return err
}

// Func is a single function inside a binary.
type Func struct {
	Name string
	Addr uint64 // virtual address of the first instruction; wasm: function index
	Size uint64 // size of the function body in bytes

	// code is the function body for formats whose text is not
	// address-sliced (wasm); nil otherwise.
	code []byte

	bin *Binary
}

// Code returns the machine code of the function. The returned slice
// aliases the binary's file mapping and must not be modified. It
// returns nil when the function lies outside the text section.
func (f *Func) Code() []byte {
	if f.code != nil {
		return f.code
	}
	b := f.bin
	if f.Addr < b.textAddr {
		return nil
	}
	// sectionSlice rejects out-of-range and overflowing (addr, size)
	// pairs, so a corrupt symbol near 2^64 cannot wrap past the check.
	return sectionSlice(b.text, f.Addr-b.textAddr, f.Size)
}

// Open maps the binary at path and parses it. It detects the file
// format from its magic bytes; currently ELF, Mach-O, PE, wasm, and
// Go compile archives are recognized.
func Open(path string) (*Binary, error) {
	data, closeMapping, err := mmapFile(path)
	if err != nil {
		return nil, err
	}
	bin, err := parse(data)
	if err != nil {
		_ = closeMapping() // the parse error is the interesting one
		return nil, fmt.Errorf("%q: %w", path, err)
	}
	bin.closeMapping = closeMapping
	return bin, nil
}

// parse dispatches on the magic bytes of a mapped binary.
func parse(data []byte) (*Binary, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("too short to be a binary")
	}
	r := bytes.NewReader(data)
	magic := string(data[:4])
	switch {
	case magic == elf.ELFMAG:
		return openELF(r, data)
	case magic == "\xcf\xfa\xed\xfe" || magic == "\xfe\xed\xfa\xcf":
		return openMachO(r, data)
	case magic[0] == 'M' && magic[1] == 'Z':
		return openPE(r, data)
	case magic == "\x00asm":
		return openWasm(data)
	case bytes.HasPrefix(data, []byte("!<arch>\n")):
		return openGoArchive(data)
	default:
		return nil, fmt.Errorf("unsupported binary format")
	}
}

// sectionSlice returns the file-backed contents of a section as a
// zero-copy slice into the mapping, or nil when the range is invalid.
func sectionSlice(data []byte, off, size uint64) []byte {
	if off > uint64(len(data)) || size > uint64(len(data))-off {
		return nil
	}
	return data[off : off+size]
}

// sizelessSym is a symbol from a format that does not record sizes
// (Mach-O, PE).
type sizelessSym struct {
	name string
	addr uint64
}

// addSizeless records functions whose sizes are unknown, inferring each
// size as the distance to the next symbol, and the end of the text
// section for the last one. Exact ranges for Go binaries come from the
// pclntab instead; this is the fallback for non-Go symbols.
func (b *Binary) addSizeless(syms []sizelessSym) {
	syms = slices.DeleteFunc(syms, func(s sizelessSym) bool {
		return s.addr < b.textAddr || s.addr >= b.textAddr+uint64(len(b.text))
	})
	slices.SortFunc(syms, func(x, y sizelessSym) int {
		return cmp.Compare(x.addr, y.addr)
	})
	for i, sym := range syms {
		end := b.textAddr + uint64(len(b.text))
		// Skip aliases at the same address (common in Mach-O and PE)
		// so they all get the real extent instead of size zero.
		for _, next := range syms[i+1:] {
			if next.addr != sym.addr {
				end = next.addr
				break
			}
		}
		b.addFunc(sym.name, sym.addr, end-sym.addr)
	}
}

// openELF loads an ELF executable.
func openELF(r io.ReaderAt, data []byte) (*Binary, error) {
	ef, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	var arch Arch
	switch ef.Machine {
	case elf.EM_X86_64:
		arch = ArchAMD64
	case elf.EM_AARCH64:
		arch = ArchARM64
	case elf.EM_386:
		arch = Arch386
	case elf.EM_S390:
		// EM_S390 also covers 31-bit s390 ELFCLASS32 objects; only
		// the 64-bit s390x variant is supported.
		if ef.Class != elf.ELFCLASS64 {
			return nil, fmt.Errorf("unsupported ELF machine %v (32-bit)", ef.Machine)
		}
		arch = ArchS390X
	case elf.EM_PPC64:
		if ef.Class != elf.ELFCLASS64 {
			return nil, fmt.Errorf("unsupported ELF machine %v (32-bit)", ef.Machine)
		}
		// The two GOARCHes differ only in byte order, recorded in
		// the ELF ident and needed later for instruction decoding.
		if ef.ByteOrder == binary.BigEndian {
			arch = ArchPPC64
		} else {
			arch = ArchPPC64LE
		}
	case elf.EM_RISCV:
		if ef.Class != elf.ELFCLASS64 {
			return nil, fmt.Errorf("unsupported ELF class %v for RISC-V", ef.Class)
		}
		arch = ArchRISCV64
	case elf.EM_LOONGARCH:
		// EM_LOONGARCH covers both 32- and 64-bit LoongArch; only
		// the 64-bit variant is supported.
		if ef.Class != elf.ELFCLASS64 {
			return nil, fmt.Errorf("unsupported ELF machine %v (32-bit)", ef.Machine)
		}
		arch = ArchLoong64
	case elf.EM_ARM:
		arch = ArchARM
	default:
		return nil, fmt.Errorf("unsupported ELF machine %v", ef.Machine)
	}

	text := ef.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section")
	}
	code := sectionSlice(data, text.Offset, text.FileSize)
	if code == nil || text.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, fmt.Errorf("unreadable .text section")
	}

	bin := &Binary{
		Arch:     arch,
		Funcs:    map[string]*Func{},
		text:     code,
		textAddr: text.Addr,
	}

	for _, sec := range ef.Sections {
		if sec.Flags&elf.SHF_ALLOC != 0 {
			bin.addRange(sec.Addr, sec.Size)
		}
	}

	syms, err := ef.Symbols()
	if err != nil && err != elf.ErrNoSymbols {
		return nil, fmt.Errorf("reading symbols: %w", err)
	}
	for _, sym := range syms {
		switch elf.ST_TYPE(sym.Info) {
		case elf.STT_FUNC:
			if sym.Size != 0 {
				bin.addFunc(sym.Name, sym.Value, sym.Size)
			}
		case elf.STT_OBJECT:
			bin.addData(sym.Name, sym.Value, sym.Size)
		}
	}
	bin.finishData()

	if sec := ef.Section(".gopclntab"); sec != nil {
		if data, err := sec.Data(); err == nil {
			bin.loadGoFuncs(data)
		}
	} else {
		// The system linker (cgo, external linking) emits no
		// dedicated section; the pclntab lands inside another data
		// section, commonly .data.rel.ro. Scan them all.
		var candidates [][]byte
		for _, sec := range ef.Sections {
			if sec.Type == elf.SHT_PROGBITS &&
				sec.Flags&elf.SHF_ALLOC != 0 && sec.Flags&elf.SHF_EXECINSTR == 0 {
				if data, err := sec.Data(); err == nil {
					candidates = append(candidates, data)
				}
			}
		}
		bin.scanPclntab(candidates...)
	}
	return bin, nil
}

// Contains reports whether addr falls inside any loadable section of
// the binary.
func (b *Binary) Contains(addr uint64) bool {
	for _, r := range b.ranges {
		if r[0] <= addr && addr < r[1] {
			return true
		}
	}
	return false
}

// dataSym is a non-function symbol. A zero size means the symbol
// extends to the next data symbol.
type dataSym struct {
	name string
	addr uint64
	size uint64
}

// addData records a data symbol.
func (b *Binary) addData(name string, addr, size uint64) {
	b.dataSyms = append(b.dataSyms, dataSym{name: name, addr: addr, size: size})
}

// finishData sorts the data symbols for lookup; call once after all
// addData calls.
func (b *Binary) finishData() {
	slices.SortFunc(b.dataSyms, func(x, y dataSym) int {
		return cmp.Compare(x.addr, y.addr)
	})
}

// DataSym resolves an address to the name, base address, and size of
// the data symbol containing it, or ("", 0, 0) when unknown. Symbols
// without a recorded size extend to the next data symbol.
func (b *Binary) DataSym(addr uint64) (name string, base, size uint64) {
	i, _ := slices.BinarySearchFunc(b.dataSyms, addr, func(s dataSym, a uint64) int {
		return cmp.Compare(s.addr, a)
	})
	// i is the first symbol at or after addr; the containing one is
	// at i-1 unless addr hits a symbol start exactly.
	if i >= len(b.dataSyms) || b.dataSyms[i].addr != addr {
		if i == 0 {
			return "", 0, 0
		}
		i--
	}
	s := b.dataSyms[i]
	end := s.addr + s.size
	if s.size == 0 {
		if i+1 < len(b.dataSyms) {
			end = b.dataSyms[i+1].addr
		} else {
			// Last symbol: bound it by its loadable section instead of
			// infinity, so unrelated high addresses don't resolve to it.
			for _, r := range b.ranges {
				if r[0] <= s.addr && s.addr < r[1] {
					end = r[1]
					break
				}
			}
		}
	}
	if addr >= end {
		return "", 0, 0
	}
	return s.name, s.addr, end - s.addr
}

// WasmName returns the name of the wasm function with the given index
// in the module's function index space (imports first, then defined
// functions). ok is false for non-wasm binaries and out-of-range
// indices.
func (b *Binary) WasmName(index uint64) (name string, ok bool) {
	if index >= uint64(len(b.wasmNames)) {
		return "", false
	}
	return b.wasmNames[index], true
}

// addRange records a loadable section's virtual address range. An end
// that would wrap past 2^64 is clamped to the top of the address space
// so Contains stays correct for corrupt section headers.
func (b *Binary) addRange(addr, size uint64) {
	if size == 0 {
		return
	}
	end := addr + size
	if end < addr {
		end = ^uint64(0)
	}
	b.ranges = append(b.ranges, [2]uint64{addr, end})
}

// addFunc records a function if it lies within the text section.
// Overflow-safe: a corrupt symbol with addr near 2^64 must not wrap
// past the bounds check.
func (b *Binary) addFunc(name string, addr, size uint64) {
	if addr < b.textAddr {
		return
	}
	off := addr - b.textAddr
	if off > uint64(len(b.text)) || size > uint64(len(b.text))-off {
		return
	}
	b.Funcs[name] = &Func{Name: name, Addr: addr, Size: size, bin: b}
}
