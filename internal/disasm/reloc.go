package disasm

import (
	"encoding/binary"

	"github.com/loov/ixdiff/internal/objfile"
)

// RelocOnly reports whether two equal-length function bodies differ
// only in relocation-bearing fields, without disassembling. A true
// result means the full normalize-and-diff pipeline would classify
// the pair as relocation-only noise; false means unknown, and the
// caller must fall back to full analysis. The lookups resolve branch
// targets so a call retargeted to a different function is never
// mistaken for relocation.
//
// Only arm64 is recognized: fixed-width words make the relocation
// fields cheap to locate. On amd64 it always returns false.
func RelocOnly(arch objfile.Arch, oldCode, newCode []byte, oldAddr, newAddr uint64, oldSym, newSym SymLookup) bool {
	if arch != objfile.ArchARM64 || len(oldCode) != len(newCode) {
		return false
	}
	return relocOnlyARM64(oldCode, newCode, oldAddr, newAddr, oldSym, newSym)
}

// arm64 instruction encodings, per the ARM ARM. Register numbers
// occupy bits 4:0 (Rd/Rt) and 9:5 (Rn).
const (
	armBMask   = 0xFC000000
	armB       = 0x14000000 // B imm26
	armBL      = 0x94000000 // BL imm26
	armADRMask = 0x9F000000
	armADRP    = 0x90000000 // ADRP immlo:30-29 immhi:23-5
	armImm12   = 0xFFF << 10
)

// relocOnlyARM64 walks both bodies word by word. Differing words are
// accepted only when the difference is confined to a field that
// relocation legitimately changes:
//
//   - B/BL displacement, when the target lies outside the function on
//     both sides (an intra-function branch that changed is real) and
//     both sides resolve to the same symbol at the same offset
//   - the ADRP page immediate
//   - a 12-bit immediate whose base register was set by an ADRP (the
//     low bits of a relocated data address)
//
// Anything else fails, leaving the decision to full analysis.
func relocOnlyARM64(oldCode, newCode []byte, oldAddr, newAddr uint64, oldSym, newSym SymLookup) bool {
	// adrp tracks which registers currently hold an ADRP page
	// address, by register number.
	var adrp uint32

	n := len(oldCode) &^ 3
	for i := 0; i < n; i += 4 {
		o := binary.LittleEndian.Uint32(oldCode[i:])
		w := binary.LittleEndian.Uint32(newCode[i:])

		switch {
		case o == w:
			// Identical; fall through to register tracking.

		case o&armBMask == armB && w&armBMask == armB,
			o&armBMask == armBL && w&armBMask == armBL:
			oldTarget := branchTarget(o, oldAddr, uint64(i))
			newTarget := branchTarget(w, newAddr, uint64(i))
			if within(oldTarget, oldAddr, uint64(len(oldCode))) ||
				within(newTarget, newAddr, uint64(len(oldCode))) {
				return false // retargeted intra-function branch
			}
			oldName, oldBase := oldSym(oldTarget)
			newName, newBase := newSym(newTarget)
			if oldName == "" || oldName != newName ||
				oldTarget-oldBase != newTarget-newBase {
				return false // different callee
			}

		case o&armADRMask == armADRP && w&armADRMask == armADRP &&
			o&0x1F == w&0x1F:
			// Page immediate differs; register updated below.

		case o&^armImm12 == w&^armImm12 && adrp&(1<<(o>>5&0x1F)) != 0:
			// Same instruction and registers, only a 12-bit
			// immediate differs, and the base register holds an
			// ADRP page address: the low bits of a moved address.

		default:
			return false
		}

		if o&armADRMask == armADRP && o == w || o&armADRMask == armADRP && w&armADRMask == armADRP {
			adrp |= 1 << (o & 0x1F)
		} else {
			// Any other instruction naming the register in its
			// destination field invalidates it. Stores name a
			// source there; over-clearing only costs precision.
			adrp &^= 1 << (o & 0x1F)
		}
	}
	// A trailing partial word must match exactly.
	for i := n; i < len(oldCode); i++ {
		if oldCode[i] != newCode[i] {
			return false
		}
	}
	return true
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
