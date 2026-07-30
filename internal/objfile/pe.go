package objfile

import (
	"debug/pe"
	"fmt"
	"io"
)

// openPE loads a PE (Windows) executable.
func openPE(r io.ReaderAt, data []byte) (*Binary, error) {
	pf, err := pe.NewFile(r)
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
	// The section's on-disk data can be padded past its virtual size.
	size := min(uint64(text.Size), uint64(text.VirtualSize))
	code := sectionSlice(data, uint64(text.Offset), size)
	if code == nil {
		return nil, fmt.Errorf("unreadable .text section")
	}

	bin := &Binary{
		Arch:     arch,
		Funcs:    map[string]*Func{},
		text:     code,
		textAddr: imageBase + uint64(text.VirtualAddress),
	}

	for _, sec := range pf.Sections {
		bin.addRange(imageBase+uint64(sec.VirtualAddress), uint64(sec.VirtualSize))
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
