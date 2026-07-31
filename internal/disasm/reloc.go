package disasm

import (
	"encoding/binary"
	"strings"

	"github.com/loov/ixdiff/internal/objfile"
)

// DataLookup resolves an address to the name, base address, and size
// of the data symbol containing it, or ("", 0, 0) when unknown. It
// matches the signature of objfile.Binary.DataSym.
type DataLookup func(addr uint64) (name string, base, size uint64)

// bigDataSym is the size above which a data symbol is treated as an
// aggregate blob whose internal offsets shift freely between builds;
// offsets into such symbols are masked rather than compared.
const bigDataSym = 4096

// sectionMarkers are linker-generated section boundary symbols; data
// resolving to them is anonymous neighboring data, not a reference to
// the marker, so such references are always masked.
var sectionMarkers = map[string]bool{
	"runtime.text": true, "runtime.etext": true,
	"runtime.rodata": true, "runtime.erodata": true,
	"runtime.types": true, "runtime.etypes": true,
	"runtime.data": true, "runtime.edata": true,
	"runtime.bss": true, "runtime.ebss": true,
	"runtime.gcdata": true, "runtime.egcdata": true,
	"runtime.gcbss": true, "runtime.egcbss": true,
	"runtime.noptrdata": true, "runtime.enoptrdata": true,
	"runtime.noptrbss": true, "runtime.enoptrbss": true,
	"runtime.covctrs": true, "runtime.ecovctrs": true,
	"runtime.itablink": true, "runtime.eitablink": true,
	"runtime.end": true, "runtime.zerobase": true,
	"runtime.rathole": true,
}

// dataMasked reports whether a resolved data symbol is untrustworthy
// for identity comparison: unresolved, an aggregate blob, a section
// marker, or linker-generated function metadata.
func dataMasked(name string, size uint64) bool {
	return name == "" || size > bigDataSym ||
		sectionMarkers[name] || strings.HasPrefix(name, "go:func")
}

// RelocOnly reports whether two equal-length function bodies differ
// only in relocation-bearing fields, without disassembling. A true
// result means the full normalize-and-diff pipeline would classify
// the pair as relocation-only noise; false means unknown, and the
// caller must fall back to full analysis. The sym lookups resolve
// branch targets and the data lookups resolve ADRP-based data
// references, so a call or load retargeted to a different symbol is
// never mistaken for relocation.
//
// Architectures without a fast path (s390x; ppc64, whose ADDIS/ADD
// pairs would need tracking analogous to arm64 ADRP) always report
// false and rely on full analysis; that costs speed, not correctness.
func RelocOnly(arch objfile.Arch, oldCode, newCode []byte, oldAddr, newAddr uint64,
	oldSym, newSym SymLookup, oldData, newData DataLookup) bool {
	if len(oldCode) != len(newCode) {
		return false
	}
	switch arch {
	case objfile.ArchARM64:
		return relocOnlyARM64(oldCode, newCode, oldAddr, newAddr, oldSym, newSym, oldData, newData)
	case objfile.ArchAMD64:
		return relocOnlyX86(oldCode, newCode, oldAddr, newAddr, oldSym, newSym, oldData, newData, 64)
	case objfile.Arch386:
		return relocOnlyX86(oldCode, newCode, oldAddr, newAddr, oldSym, newSym, oldData, newData, 32)
	default:
		// No fast path for s390x: its variable-length encoding has no
		// cheap word-by-word walk, so triage always falls back to
		// full analysis. Only a missed speedup, never wrong.
		return false
	}
}

// arm64 instruction encodings, per the ARM ARM. Register numbers
// occupy bits 4:0 (Rd/Rt) and 9:5 (Rn).
const (
	armBMask   = 0xFC000000
	armB       = 0x14000000 // B imm26
	armBL      = 0x94000000 // BL imm26
	armADRMask = 0x9F000000
	armADRP    = 0x90000000 // ADRP immlo:30-29 immhi:23-5
	// ADD (immediate, 64-bit, no flags, no shift): imm12 in 21:10.
	armAddMask = 0xFFC00000
	armAdd     = 0x91000000
	// Load/store register, unsigned immediate: imm12 in 21:10,
	// scaled by size (bits 31:30); bit 26 set means SIMD.
	armLdStMask = 0x3B000000
	armLdSt     = 0x39000000
	armSIMD     = 1 << 26
	armImm12    = 0xFFF << 10
)

// relocOnlyARM64 walks both bodies word by word. Differing words are
// accepted only when the difference is confined to a field that
// relocation legitimately changes:
//
//   - B/BL displacement, when the target lies outside the function on
//     both sides (an intra-function branch that changed is real) and
//     both sides resolve to the same symbol at the same offset
//   - the ADRP page immediate
//   - the 12-bit immediate of an ADD or load/store based on an ADRP
//     register, when the combined address resolves to the same data
//     symbol and offset on both sides
//
// Anything else — including any other use of an ADRP-based register,
// whose address semantics this fast path cannot follow — fails,
// leaving the decision to full analysis.
func relocOnlyARM64(oldCode, newCode []byte, oldAddr, newAddr uint64,
	oldSym, newSym SymLookup, oldData, newData DataLookup) bool {
	// tracked marks registers holding an ADRP page address; oldPage
	// and newPage hold that page per side.
	var tracked uint32
	var oldPage, newPage [32]uint64

	n := len(oldCode) &^ 3
	for i := 0; i < n; i += 4 {
		o := binary.LittleEndian.Uint32(oldCode[i:])
		w := binary.LittleEndian.Uint32(newCode[i:])
		rn := o >> 5 & 0x1F

		switch {
		case o&armADRMask == armADRP && w&armADRMask == armADRP && o&0x1F == w&0x1F:
			rd := o & 0x1F
			oldPage[rd] = adrpTarget(o, oldAddr+uint64(i))
			newPage[rd] = adrpTarget(w, newAddr+uint64(i))
			tracked |= 1 << rd
			continue

		case o == w && tracked&(1<<rn) == 0:
			// Identical and independent of any page register.

		case o&armBMask == armB && w&armBMask == armB,
			o&armBMask == armBL && w&armBMask == armBL:
			oldTarget := branchTarget(o, oldAddr, uint64(i))
			newTarget := branchTarget(w, newAddr, uint64(i))
			intraOld := within(oldTarget, oldAddr, uint64(len(oldCode)))
			intraNew := within(newTarget, newAddr, uint64(len(oldCode)))
			if intraOld || intraNew {
				if o != w || !intraOld || !intraNew {
					return false // retargeted intra-function branch
				}
				break
			}
			oldName, oldBase := oldSym(oldTarget)
			newName, newBase := newSym(newTarget)
			if oldName == "" || oldName != newName ||
				oldTarget-oldBase != newTarget-newBase {
				return false // different callee
			}

		case o&^armImm12 == w&^armImm12 && tracked&(1<<rn) != 0 &&
			o&armAddMask == armAdd && w&armAddMask == armAdd:
			if !sameData(oldPage[rn]+uint64(o>>10&0xFFF), newPage[rn]+uint64(w>>10&0xFFF),
				oldData, newData) {
				return false
			}

		case o&^armImm12 == w&^armImm12 && tracked&(1<<rn) != 0 &&
			o&armLdStMask == armLdSt && o&armSIMD == 0:
			scale := o >> 30
			if !sameData(oldPage[rn]+uint64(o>>10&0xFFF)<<scale, newPage[rn]+uint64(w>>10&0xFFF)<<scale,
				oldData, newData) {
				return false
			}

		default:
			// Real change, or an ADRP-based access this fast path
			// cannot resolve.
			return false
		}

		// Any non-ADRP instruction naming a page register in its
		// destination field invalidates it. Stores name a source
		// there; over-clearing only costs precision.
		tracked &^= 1 << (o & 0x1F)
	}
	// A trailing partial word must match exactly.
	for i := n; i < len(oldCode); i++ {
		if oldCode[i] != newCode[i] {
			return false
		}
	}
	return true
}

// sameData reports whether two addresses render identically under the
// full path's data-reference rules: resolution is trusted only into
// small, precisely-sized, non-marker symbols, where name and offset
// must match; everything else is masked on both sides and therefore
// matches only if both sides are masked.
func sameData(oldAddr, newAddr uint64, oldData, newData DataLookup) bool {
	oldName, oldBase, oldSize := oldData(oldAddr)
	newName, newBase, newSize := newData(newAddr)
	oldMasked := dataMasked(oldName, oldSize)
	newMasked := dataMasked(newName, newSize)
	if oldMasked || newMasked {
		return oldMasked == newMasked
	}
	return maskGenNumber(oldName) == maskGenNumber(newName) &&
		oldAddr-oldBase == newAddr-newBase
}

// adrpTarget computes the page address produced by an ADRP word at pc.
func adrpTarget(word uint32, pc uint64) uint64 {
	immlo := word >> 29 & 3
	immhi := word >> 5 & 0x7FFFF
	imm := int64(int32(immhi<<13|immlo<<11)) >> 11 // sign-extend 21 bits
	return pc&^0xFFF + uint64(imm)<<12
}

// branchTarget computes the absolute target of the B/BL word at
// offset off. imm26 is a signed word offset from the instruction.
func branchTarget(word uint32, funcAddr, off uint64) uint64 {
	imm := int64(int32(word<<6) >> 6) // sign-extend 26 bits
	return funcAddr + off + uint64(imm*4)
}

// within reports whether addr lies in [base, base+size).
func within(addr, base, size uint64) bool {
	return addr >= base && addr < base+size
}
