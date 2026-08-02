// Package ixdiff compares the assembly of two compiled binaries.
//
// It loads ELF, Mach-O, PE, wasm, and Go compile-archive files, pairs
// their functions by name (detecting likely renames), and classifies
// every pair: byte-identical, changed, differing only by relocation,
// added, or removed. Changed pairs carry a normalized instruction-level
// edit script whose labels and moved-address operands are stable across
// layout shifts, so the diff shows real code generation changes rather
// than linker noise.
//
// Typical use:
//
//	old, err := ixdiff.Open("app.v1")
//	new, err := ixdiff.Open("app.v2")
//	diff, err := ixdiff.Compare(old, new, nil)
//	for _, p := range diff.Pairs() {
//		if p.State == ixdiff.Changed {
//			lines, err := diff.Lines(p)
//			...
//		}
//	}
package ixdiff

import (
	"cmp"
	"slices"
	"sync"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/objfile"
)

// Binary is a loaded binary, backed by a read-only memory mapping of
// the file. Close releases the mapping; Func.Code slices become
// invalid afterwards.
type Binary struct {
	path string
	obj  *objfile.Binary

	// once guards the lazily built function views below.
	once   sync.Once
	funcs  []*Func
	byName map[string]*Func
	lookup disasm.SymLookup
}

// Open maps the binary at path and parses it. The file format is
// detected from its magic bytes; ELF, Mach-O, PE, wasm, and Go compile
// archives are recognized.
func Open(path string) (*Binary, error) {
	obj, err := objfile.Open(path)
	if err != nil {
		return nil, err
	}
	return &Binary{path: path, obj: obj}, nil
}

// Close releases the binary's file mapping.
func (b *Binary) Close() error { return b.obj.Close() }

// Path returns the path the binary was opened from.
func (b *Binary) Path() string { return b.path }

// Arch returns the Go name of the binary's instruction set, such as
// "amd64" or "arm64".
func (b *Binary) Arch() string { return b.obj.Arch.String() }

// init builds the function views and the symbol lookup once.
func (b *Binary) init() {
	b.once.Do(func() {
		b.byName = make(map[string]*Func, len(b.obj.Funcs))
		b.funcs = make([]*Func, 0, len(b.obj.Funcs))
		for name, fn := range b.obj.Funcs {
			f := &Func{
				Name:    name,
				Package: pkgOf(name),
				Addr:    fn.Addr,
				Size:    int64(fn.Size),
				obj:     fn,
				bin:     b,
			}
			b.byName[name] = f
			b.funcs = append(b.funcs, f)
		}
		// Ties broken by name so aliased symbols at the same address
		// order deterministically.
		slices.SortFunc(b.funcs, func(x, y *Func) int {
			if x.Addr != y.Addr {
				return cmp.Compare(x.Addr, y.Addr)
			}
			return cmp.Compare(x.Name, y.Name)
		})
		b.lookup = disasm.Lookup(b.obj)
	})
}

// symLookup returns the memoized symbol lookup for decoding.
func (b *Binary) symLookup() disasm.SymLookup {
	b.init()
	return b.lookup
}

// Funcs returns every function of the binary in address order. The
// returned slice is shared and must not be modified.
func (b *Binary) Funcs() []*Func {
	b.init()
	return b.funcs
}

// Func returns the function with the exact symbol name.
func (b *Binary) Func(name string) (*Func, bool) {
	b.init()
	f, ok := b.byName[name]
	return f, ok
}

// TextBytes returns the total size of all functions in bytes.
func (b *Binary) TextBytes() int64 {
	var total int64
	for _, f := range b.Funcs() {
		total += f.Size
	}
	return total
}

// Padding is the space between functions, split by gap size: Align
// holds gaps of at most 64 bytes (ordinary function alignment) and
// Large the rest, which usually indicates non-symbol code or data
// interleaved with the text section.
type Padding struct {
	Align, Large int64
}

// Padding sums the gaps between the address-sorted functions of the
// binary. Go compile archives have no memory layout, so their padding
// is zero.
func (b *Binary) Padding() Padding {
	var p Padding
	if b.obj.NoLayout {
		return p
	}
	end := uint64(0)
	first := true
	for _, f := range b.Funcs() {
		if !first && f.Addr > end {
			if gap := int64(f.Addr - end); gap <= 64 {
				p.Align += gap
			} else {
				p.Large += gap
			}
		}
		first = false
		if e := f.Addr + uint64(f.Size); e > end {
			end = e
		}
	}
	return p
}

// Func is a single function inside a binary.
type Func struct {
	Name    string
	Package string // the package part of Name, e.g. "net/url"
	Addr    uint64 // virtual address; wasm: function index; archives: file offset
	Size    int64  // size of the function body in bytes

	obj *objfile.Func
	bin *Binary
}

// Code returns the machine code of the function. The returned slice
// aliases the binary's file mapping and must not be modified.
func (f *Func) Code() []byte { return f.obj.Code() }

// Inst is a single decoded instruction.
type Inst struct {
	Addr uint64 // virtual address of the instruction
	Text string // Go-syntax rendering, e.g. "CALL runtime.mallocgc(SB)"
}

// Text disassembles the function, resolving call and data targets to
// symbol names.
func (f *Func) Text() ([]Inst, error) {
	insts, err := f.decode()
	if err != nil {
		return nil, err
	}
	out := make([]Inst, len(insts))
	for i, in := range insts {
		out[i] = Inst{Addr: in.Addr, Text: in.Text}
	}
	return out, nil
}

// Ops disassembles the function and counts its instruction mnemonics.
// BYTE pseudo-instructions (padding and undecodable bytes) are
// excluded: they are not code.
func (f *Func) Ops() (OpCount, error) {
	insts, err := f.decode()
	if err != nil {
		return nil, err
	}
	return countOps(ops(insts)), nil
}

// decode disassembles the function with the binary's memoized lookup.
func (f *Func) decode() ([]disasm.Inst, error) {
	return disasm.Decode(f.bin.obj.Arch, f.Code(), f.Addr, f.bin.symLookup())
}

// ops extracts the mnemonics of insts, skipping BYTE pseudo-
// instructions: padding is not code and would pollute the statistics.
func ops(insts []disasm.Inst) []string {
	out := make([]string, 0, len(insts))
	for _, in := range insts {
		if in.Op != "BYTE" {
			out = append(out, in.Op)
		}
	}
	return out
}

// countInsts counts real instructions, excluding BYTE padding.
func countInsts(insts []disasm.Inst) int {
	n := 0
	for _, in := range insts {
		if in.Op != "BYTE" {
			n++
		}
	}
	return n
}
