package objfile

import (
	"debug/macho"
	"fmt"
	"io"
	"strings"
)

// openMachO loads a Mach-O executable.
func openMachO(r io.ReaderAt, data []byte) (*Binary, error) {
	mf, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}

	var arch Arch
	switch mf.Cpu {
	case macho.CpuAmd64:
		arch = ArchAMD64
	case macho.CpuArm64:
		arch = ArchARM64
	default:
		return nil, fmt.Errorf("unsupported Mach-O cpu %v", mf.Cpu)
	}

	text := mf.Section("__text")
	if text == nil {
		return nil, fmt.Errorf("no __text section")
	}
	code := sectionSlice(data, uint64(text.Offset), text.Size)
	if code == nil {
		return nil, fmt.Errorf("unreadable __text section")
	}

	bin := &Binary{
		Arch:     arch,
		Funcs:    map[string]*Func{},
		text:     code,
		textAddr: text.Addr,
	}

	for _, sec := range mf.Sections {
		bin.addRange(sec.Addr, sec.Size)
	}

	if mf.Symtab != nil {
		var syms []sizelessSym
		for _, sym := range mf.Symtab.Syms {
			// 0xe0 masks the N_STAB debugging bits; such
			// entries describe source info, not functions.
			if sym.Type&0xe0 != 0 {
				continue
			}
			// Mach-O prefixes symbol names with an underscore.
			name := strings.TrimPrefix(sym.Name, "_")
			syms = append(syms, sizelessSym{name: name, addr: sym.Value})
		}
		bin.addSizeless(syms)
	}

	if sec := mf.Section("__gopclntab"); sec != nil {
		if data, err := sec.Data(); err == nil {
			bin.loadGoFuncs(data)
		}
	}
	return bin, nil
}
