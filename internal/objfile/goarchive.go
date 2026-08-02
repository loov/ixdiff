package objfile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// A Go compile archive (go build -o pkg.a, go tool compile) is a Unix
// ar archive holding __.PKGDEF plus one or more Go object files in the
// goobj format of cmd/internal/goobj. Only the current format version
// ("\x00go120ld", written since Go 1.20) is supported; other versions
// error rather than being misread.
//
// Archives are relocatable: symbols have no virtual addresses, and
// relocation sites in the code hold zeros or addends instead of final
// addresses. Func.Addr is the deterministic file offset of the symbol's
// code within the archive, and call/data operands generally read as 0
// until linked; the diff normalizer already masks moved-address
// operands, so this loses little in practice. Data symbols and section
// ranges are not populated.

// goobj layout constants, from cmd/internal/goobj/objfile.go.
const (
	goobjMagic   = "\x00go120ld" // current object format version
	goobjNumBlk  = 19            // number of block offsets in the header
	goobjHdrSize = 8 + 8 + 4 + 4*goobjNumBlk

	// Block indices used here; symbol definition blocks 3..6
	// (Symdef, Hashed64def, Hasheddef, Nonpkgdef) are contiguous.
	goobjBlkSymdef    = 3
	goobjBlkNonpkgref = 7
	goobjBlkDataIdx   = 13
	goobjBlkData      = 16

	goobjSymSize = 21 // encoded symbol definition size

	// Symbol types (cmd/internal/objabi.SymKind) and flags.
	goobjSTEXT          = 1
	goobjSTEXTFIPS      = 2
	goobjFlagABIWrapper = 1 << 6 // Sym.Flag2: compiler-generated ABI bridge
)

// openGoArchive loads a Go compile archive. See the file comment above
// for what is and is not populated.
func openGoArchive(data []byte) (*Binary, error) {
	bin := &Binary{Funcs: map[string]*Func{}, NoLayout: true}
	off := uint64(len("!<arch>\n"))
	for off < uint64(len(data)) {
		hdr := sectionSlice(data, off, 60)
		if hdr == nil {
			return nil, fmt.Errorf("truncated archive entry header")
		}
		if !bytes.Equal(hdr[58:60], []byte("`\n")) {
			return nil, fmt.Errorf("corrupt archive entry header")
		}
		name := strings.TrimRight(string(hdr[0:16]), " ")
		size, err := strconv.ParseUint(strings.TrimRight(string(hdr[48:58]), " "), 10, 63)
		if err != nil {
			return nil, fmt.Errorf("corrupt archive entry size: %w", err)
		}
		entry := sectionSlice(data, off+60, size)
		if entry == nil {
			return nil, fmt.Errorf("truncated archive entry %q", name)
		}
		if name != "__.PKGDEF" && bytes.HasPrefix(entry, []byte("go object ")) {
			arch, err := bin.loadGoObj(entry, off+60)
			if err != nil {
				return nil, fmt.Errorf("archive entry %q: %w", name, err)
			}
			if bin.Arch == ArchUnknown {
				bin.Arch = arch
			} else if bin.Arch != arch {
				return nil, fmt.Errorf("mixed architectures in archive: %v and %v", bin.Arch, arch)
			}
		}
		off += 60 + size + size&1 // entries are 2-byte aligned
	}
	if bin.Arch == ArchUnknown {
		return nil, fmt.Errorf("no Go object files in archive")
	}
	return bin, nil
}

// loadGoObj parses one Go object file entry, adding its text symbols
// to b, and returns the architecture recorded in the entry's textual
// header. base is the entry's file offset within the archive, used to
// give symbols deterministic archive-unique addresses.
func (b *Binary) loadGoObj(entry []byte, base uint64) (Arch, error) {
	// The textual header ("go object <goos> <goarch> <version> ...\n")
	// ends with "\n!\n"; the binary goobj data follows.
	end := bytes.Index(entry, []byte("\n!\n"))
	if end < 0 {
		return ArchUnknown, fmt.Errorf("truncated object header")
	}
	fields := strings.Fields(string(entry[:end]))
	if len(fields) < 4 {
		return ArchUnknown, fmt.Errorf("malformed object header %q", entry[:end])
	}
	arch := goarchArch(fields[3])
	if arch == ArchUnknown {
		return ArchUnknown, fmt.Errorf("unsupported architecture %q", fields[3])
	}

	obj := entry[end+3:]
	base += uint64(end + 3)
	if len(obj) < len(goobjMagic) {
		return ArchUnknown, fmt.Errorf("truncated object file")
	}
	if magic := string(obj[:8]); magic != goobjMagic {
		if strings.HasPrefix(magic, "\x00go1") {
			return ArchUnknown, fmt.Errorf("unsupported Go object version %q (built by a different Go toolchain)", magic[1:])
		}
		return ArchUnknown, fmt.Errorf("not a Go object file")
	}
	if len(obj) < goobjHdrSize {
		return ArchUnknown, fmt.Errorf("truncated object file")
	}

	// Block offsets follow the magic, fingerprint, and flags. Validate
	// once that they are non-decreasing and inside the entry, so all
	// later block arithmetic below stays in bounds.
	var blk [goobjNumBlk]uint32
	for i := range blk {
		blk[i] = binary.LittleEndian.Uint32(obj[8+8+4+4*i:])
		if uint64(blk[i]) > uint64(len(obj)) || i > 0 && blk[i] < blk[i-1] {
			return ArchUnknown, fmt.Errorf("corrupt object block offsets")
		}
	}

	// The four symbol definition blocks are contiguous, so the i-th of
	// the ndef symbols lives at blk[Symdef]+i*SymSize. DataIdx holds
	// ndef+1 offsets into the Data block, one per symbol plus the end.
	ndef := uint64(blk[goobjBlkNonpkgref]-blk[goobjBlkSymdef]) / goobjSymSize
	dataIdx := obj[blk[goobjBlkDataIdx]:blk[goobjBlkDataIdx+1]]
	dataBlk := obj[blk[goobjBlkData]:blk[goobjBlkData+1]]
	if uint64(len(dataIdx)) < (ndef+1)*4 {
		return ArchUnknown, fmt.Errorf("corrupt object data index")
	}
	for i := range ndef {
		sym := obj[uint64(blk[goobjBlkSymdef])+i*goobjSymSize:]
		if typ := sym[10]; typ != goobjSTEXT && typ != goobjSTEXTFIPS {
			continue
		}
		if sym[12]&goobjFlagABIWrapper != 0 {
			continue // synthetic bridge; the real body has the same name
		}
		nameLen := binary.LittleEndian.Uint32(sym)
		nameOff := binary.LittleEndian.Uint32(sym[4:])
		name := string(sectionSlice(obj, uint64(nameOff), uint64(nameLen)))
		if name == "" {
			continue
		}
		lo := binary.LittleEndian.Uint32(dataIdx[i*4:])
		hi := binary.LittleEndian.Uint32(dataIdx[i*4+4:])
		if hi < lo {
			return ArchUnknown, fmt.Errorf("corrupt object data index")
		}
		code := sectionSlice(dataBlk, uint64(lo), uint64(hi-lo))
		if len(code) == 0 {
			continue // declared or assembly-defined elsewhere
		}
		b.Funcs[name] = &Func{
			Name: name,
			Addr: base + uint64(blk[goobjBlkData]) + uint64(lo),
			Size: uint64(len(code)),
			code: code,
			bin:  b,
		}
	}
	return arch, nil
}

// goarchArch maps a GOARCH name from the object header to an Arch,
// returning ArchUnknown for unsupported architectures.
func goarchArch(goarch string) Arch {
	for a := ArchUnknown + 1; a <= ArchWasm; a++ {
		if a.String() == goarch {
			return a
		}
	}
	return ArchUnknown
}
