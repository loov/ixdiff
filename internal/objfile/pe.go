package objfile

import (
	"debug/pe"
	"fmt"
	"os"
)

// openPE loads a PE (Windows) executable.
func openPE(f *os.File) (*Binary, error) {
	pf, err := pe.NewFile(f)
	if err != nil {
		return nil, err
	}

	var arch Arch
	switch pf.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = ArchAMD64
	case pe.IMAGE_FILE_MACHINE_ARM64:
		arch = ArchARM64
	default:
		return nil, fmt.Errorf("unsupported PE machine %#x", pf.Machine)
	}

	var imageBase uint64
	switch hdr := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		imageBase = hdr.ImageBase
	case *pe.OptionalHeader32:
		imageBase = uint64(hdr.ImageBase)
	default:
		return nil, fmt.Errorf("missing PE optional header")
	}

	text := pf.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section")
	}
	code, err := text.Data()
	if err != nil {
		return nil, fmt.Errorf("reading .text: %w", err)
	}
	// The section's on-disk data can be padded past its virtual size.
	if uint64(text.VirtualSize) < uint64(len(code)) {
		code = code[:text.VirtualSize]
	}

	bin := &Binary{
		Arch:     arch,
		Funcs:    map[string]*Func{},
		text:     code,
		textAddr: imageBase + uint64(text.VirtualAddress),
	}

	// COFF symbol values are offsets within their section; SectionNumber
	// is 1-based. Only symbols in .text are functions of interest.
	textIndex := -1
	for i, sec := range pf.Sections {
		if sec.Name == ".text" {
			textIndex = i + 1
			break
		}
	}
	var syms []sizelessSym
	for _, sym := range pf.Symbols {
		if int(sym.SectionNumber) != textIndex {
			continue
		}
		syms = append(syms, sizelessSym{
			name: sym.Name,
			addr: imageBase + uint64(text.VirtualAddress) + uint64(sym.Value),
		})
	}
	bin.addSizeless(syms)

	// PE has no pclntab section; scan the data sections for its header.
	for _, name := range []string{".rdata", ".data"} {
		sec := pf.Section(name)
		if sec == nil {
			continue
		}
		if data, err := sec.Data(); err == nil {
			if tab := findPclntab(data); tab != nil {
				bin.loadGoFuncs(tab)
				break
			}
		}
	}
	return bin, nil
}
