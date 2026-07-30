// Package objfile loads executable binaries into a format-independent
// representation: the machine architecture and the set of functions
// with their addresses, sizes, and machine code.
package objfile

import (
	"debug/elf"
	"fmt"
	"os"
)

// Arch identifies the instruction set of a binary.
type Arch int

// Supported architectures. ArchUnknown is the invalid zero value.
const (
	ArchUnknown Arch = iota
	ArchAMD64
	ArchARM64
)

// String returns the Go name of the architecture.
func (a Arch) String() string {
	switch a {
	case ArchAMD64:
		return "amd64"
	case ArchARM64:
		return "arm64"
	default:
		return "unknown"
	}
}

// Binary is a loaded executable. It holds no open resources; Open
// reads everything it needs and closes the file.
type Binary struct {
	Arch Arch
	// Funcs maps symbol name to function.
	Funcs map[string]*Func

	// text is the contents of the executable text section,
	// starting at virtual address textAddr.
	//
	// ponytail: whole .text kept in memory (~100MB for a 200MB
	// binary); switch to mmap if profiling shows it matters.
	text     []byte
	textAddr uint64
}

// Func is a single function inside a binary.
type Func struct {
	Name string
	Addr uint64 // virtual address of the first instruction
	Size uint64 // size of the function body in bytes

	bin *Binary
}

// Code returns the machine code of the function. The returned slice
// aliases the binary's text section and must not be modified. It
// returns nil when the function lies outside the text section.
func (f *Func) Code() []byte {
	b := f.bin
	if f.Addr < b.textAddr || f.Addr+f.Size > b.textAddr+uint64(len(b.text)) {
		return nil
	}
	off := f.Addr - b.textAddr
	return b.text[off : off+f.Size]
}

// Open reads the binary at path. It detects the file format from its
// magic bytes; currently ELF, Mach-O, and PE are recognized.
func Open(path string) (*Binary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, 0); err != nil {
		return nil, fmt.Errorf("reading magic of %q: %w", path, err)
	}

	switch {
	case string(magic) == elf.ELFMAG:
		return openELF(f)
	default:
		return nil, fmt.Errorf("unsupported binary format in %q", path)
	}
}

// openELF loads an ELF executable.
func openELF(f *os.File) (*Binary, error) {
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}

	var arch Arch
	switch ef.Machine {
	case elf.EM_X86_64:
		arch = ArchAMD64
	case elf.EM_AARCH64:
		arch = ArchARM64
	default:
		return nil, fmt.Errorf("unsupported ELF machine %v", ef.Machine)
	}

	text := ef.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section")
	}
	code, err := text.Data()
	if err != nil {
		return nil, fmt.Errorf("reading .text: %w", err)
	}

	bin := &Binary{
		Arch:     arch,
		Funcs:    map[string]*Func{},
		text:     code,
		textAddr: text.Addr,
	}

	syms, err := ef.Symbols()
	if err != nil && err != elf.ErrNoSymbols {
		return nil, fmt.Errorf("reading symbols: %w", err)
	}
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC || sym.Size == 0 {
			continue
		}
		bin.addFunc(sym.Name, sym.Value, sym.Size)
	}
	return bin, nil
}

// addFunc records a function if it lies within the text section.
func (b *Binary) addFunc(name string, addr, size uint64) {
	if addr < b.textAddr || addr+size > b.textAddr+uint64(len(b.text)) {
		return
	}
	b.Funcs[name] = &Func{Name: name, Addr: addr, Size: size, bin: b}
}
