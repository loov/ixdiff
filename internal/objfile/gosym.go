package objfile

import (
	"bytes"
	"debug/gosym"
)

// loadGoFuncs parses a Go runtime pclntab and records the functions it
// describes. It gives exact function ranges even for stripped binaries
// and overrides symbol-table entries, whose sizes may be inferred
// (Mach-O, PE). Parsing is best-effort: on failure the symbol-table
// functions loaded earlier simply remain in place.
func (b *Binary) loadGoFuncs(pclntab []byte) {
	if len(pclntab) == 0 {
		return
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(pclntab, b.textAddr))
	if err != nil {
		return
	}
	for _, fn := range tab.Funcs {
		b.addFunc(fn.Name, fn.Entry, fn.End-fn.Entry)
	}
}

// pclntabMagics are the little-endian header magics of pclntab
// versions, each followed by two zero bytes as in the real header.
var pclntabMagics = [][]byte{
	{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00}, // Go 1.20+
	{0xf0, 0xff, 0xff, 0xff, 0x00, 0x00}, // Go 1.18–1.19
	{0xfa, 0xff, 0xff, 0xff, 0x00, 0x00}, // Go 1.16–1.17
}

// scanPclntab scans the contents of candidate sections for a pclntab
// header and loads the first hit. It is the fallback for binaries
// without a dedicated pclntab section: PE always, and ELF when the
// system linker (cgo, external linking) merged the pclntab into
// another data section.
func (b *Binary) scanPclntab(sections ...[]byte) {
	for _, data := range sections {
		if tab := findPclntab(data); tab != nil {
			b.loadGoFuncs(tab)
			return
		}
	}
}

// findPclntab locates a pclntab inside data by scanning for its header:
// a version magic followed by a plausible pc quantum and pointer size.
func findPclntab(data []byte) []byte {
	for _, magic := range pclntabMagics {
		for off := 0; ; {
			i := bytes.Index(data[off:], magic)
			if i < 0 {
				break
			}
			off += i
			if off+8 <= len(data) {
				quantum, ptrsize := data[off+6], data[off+7]
				if (quantum == 1 || quantum == 4) && ptrsize == 8 {
					return data[off:]
				}
			}
			off += len(magic)
		}
	}
	return nil
}
