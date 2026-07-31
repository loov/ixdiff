package disasm

import "encoding/binary"

// relocOnlyARM walks both 32-bit ARM bodies word by word. Differing
// words are accepted only when the difference is confined to a field
// that relocation legitimately changes:
//
//   - B/BL displacement, when the target lies outside the function on
//     both sides (an intra-function branch that changed is real) and
//     both sides resolve to the same symbol at the same offset
//   - a literal-pool word, when both sides resolve to the same data
//     symbol at the same offset; identical pool words must also
//     resolve consistently, since the same address can name different
//     symbols per side
//
// Anything else fails, leaving the decision to full analysis.
func relocOnlyARM(oldCode, newCode []byte, oldAddr, newAddr uint64,
	oldSym, newSym SymLookup, oldData, newData DataLookup) bool {
	pool := armPool(oldCode)
	n := len(oldCode) &^ 3
	for i := 0; i < n; i += 4 {
		o := binary.LittleEndian.Uint32(oldCode[i:])
		w := binary.LittleEndian.Uint32(newCode[i:])

		switch {
		case pool[i]:
			// A pool word holds an absolute constant patched by
			// relocation when it is an address.
			if o == w {
				if !sameData(uint64(o), uint64(w), oldData, newData) {
					return false // same value, different symbol per side
				}
				continue
			}
			// Differing values must both resolve to the same real data
			// symbol: unresolved values render as raw or masked hex,
			// whose equality this fast path cannot judge without the
			// address ranges of the binaries.
			oldName, oldBase, oldSize := oldData(uint64(o))
			newName, newBase, newSize := newData(uint64(w))
			if dataMasked(oldName, oldSize) || dataMasked(newName, newSize) ||
				maskGenNumber(oldName) != maskGenNumber(newName) ||
				uint64(o)-oldBase != uint64(w)-newBase {
				return false
			}

		case o == w:
			// Identical and position-independent.

		case armBranch(o) && armBranch(w) && o&0xFF000000 == w&0xFF000000:
			// B/BL with the same condition and link bit.
			oldTarget := armBranchTarget(o, oldAddr, uint64(i))
			newTarget := armBranchTarget(w, newAddr, uint64(i))
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

		default:
			return false
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

// armBranch reports whether word encodes a conditional B or BL. The
// cond=0b1111 space (BLX immediate) is excluded.
func armBranch(word uint32) bool {
	return word>>28 != 0xF && word>>25&7 == 5
}

// armBranchTarget computes the absolute target of the B/BL word at
// offset off. imm24 is a signed word offset from pc, which on arm
// reads eight bytes ahead of the instruction.
func armBranchTarget(word uint32, funcAddr, off uint64) uint64 {
	imm := int64(int32(word<<8) >> 8) // sign-extend 24 bits
	return funcAddr + off + 8 + uint64(imm*4)
}
