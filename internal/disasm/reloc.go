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
// branch targets and the data lookups resolve data references
// (page-based ADRP/AUIPC/PCALAU12I pairs, literal-pool words on arm),
// so a call or load retargeted to a different symbol is never
// mistaken for relocation.
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
	case objfile.ArchRISCV64:
		return relocOnlyRISCV64(oldCode, newCode, oldAddr, newAddr, oldSym, newSym, oldData, newData)
	case objfile.ArchLoong64:
		return relocOnlyLoong64(oldCode, newCode, oldAddr, newAddr, oldSym, newSym, oldData, newData)
	case objfile.ArchARM:
		return relocOnlyARM(oldCode, newCode, oldAddr, newAddr, oldSym, newSym, oldData, newData)
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
			// Register 31 in the Rd field of ADRP is XZR: such an
			// ADRP materializes nothing, and a later load/store
			// whose base field holds 31 means SP, not a page.
			if rd := o & 0x1F; rd != 31 {
				oldPage[rd] = adrpTarget(o, oldAddr+uint64(i))
				newPage[rd] = adrpTarget(w, newAddr+uint64(i))
				tracked |= 1 << rd
			}
			continue

		case o&armBMask == armB && w&armBMask == armB,
			o&armBMask == armBL && w&armBMask == armBL:
			// Checked before the identical-word shortcut: with the
			// functions at different addresses, an identical
			// displacement reaches a different target, which can
			// resolve to a different symbol per side.
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

		case o == w && tracked&(1<<rn) == 0:
			// Identical and independent of any page register.

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

// riscv64 instruction encodings, per the RISC-V ISA manual. The opcode
// occupies bits 6:0, rd bits 11:7, and rs1 bits 19:15.
const (
	rvOpMask = 0x7F
	rvAUIPC  = 0x17
	rvJAL    = 0x6F
	rvLoad   = 0x03 // LB/LH/LW/LD and unsigned variants
	rvStore  = 0x23 // SB/SH/SW/SD
	// ADDI: opcode OP-IMM with funct3 0.
	rvAddiMask = 0x707F
	rvADDI     = 0x13
	rvRdMask   = 0x1F << 7
	rvImmI     = 0xFFF << 20 // I-type immediate: bits 31:20
	rvImmS     = 0xFE00_0F80 // S-type immediate: bits 31:25 and 11:7
)

// relocOnlyRISCV64 walks both bodies word by word, mirroring
// relocOnlyARM64 with riscv64's AUIPC-based address materialization.
// Differing words are accepted only when the difference is confined to
// a field that relocation legitimately changes:
//
//   - JAL displacement, when the target lies outside the function on
//     both sides and both sides resolve to the same symbol at the same
//     offset
//   - the AUIPC upper immediate
//   - the 12-bit immediate of an ADDI, load, or store based on an
//     AUIPC register, when the combined address resolves to the same
//     data symbol and offset on both sides
//
// Anything else — including any other use of an AUIPC-based register,
// whose address semantics this fast path cannot follow — fails,
// leaving the decision to full analysis. The walk assumes 4-byte
// instructions; Go does not emit the compressed extension, and a
// misparse can only produce a spurious false, never a wrong true,
// because differing compressed words fail the acceptable-field checks.
func relocOnlyRISCV64(oldCode, newCode []byte, oldAddr, newAddr uint64,
	oldSym, newSym SymLookup, oldData, newData DataLookup) bool {
	// tracked marks registers holding an AUIPC-derived address;
	// oldPage and newPage hold that address per side.
	var tracked uint32
	var oldPage, newPage [32]uint64

	n := len(oldCode) &^ 3
	for i := 0; i < n; i += 4 {
		o := binary.LittleEndian.Uint32(oldCode[i:])
		w := binary.LittleEndian.Uint32(newCode[i:])
		rs1 := o >> 15 & 0x1F

		switch {
		case o&rvOpMask == rvAUIPC && w&rvOpMask == rvAUIPC && o&rvRdMask == w&rvRdMask:
			// X0 is the hardwired zero register: an AUIPC writing it
			// materializes nothing, and instructions reading X0
			// afterwards read a constant zero, not the page.
			if rd := o >> 7 & 0x1F; rd != 0 {
				oldPage[rd] = auipcTarget(o, oldAddr+uint64(i))
				newPage[rd] = auipcTarget(w, newAddr+uint64(i))
				tracked |= 1 << rd
			}
			continue

		case o&rvOpMask == rvJAL && w&rvOpMask == rvJAL && o&rvRdMask == w&rvRdMask:
			// Checked before the identical-word shortcut: with the
			// functions at different addresses, an identical
			// displacement reaches a different target, which can
			// resolve to a different symbol per side.
			oldTarget := jalTarget(o, oldAddr, uint64(i))
			newTarget := jalTarget(w, newAddr, uint64(i))
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

		case o == w && tracked&(1<<rs1) == 0:
			// Identical and independent of any page register.

		case o&^uint32(rvImmI) == w&^uint32(rvImmI) && tracked&(1<<rs1) != 0 &&
			(o&rvAddiMask == rvADDI || o&rvOpMask == rvLoad):
			if !sameData(oldPage[rs1]+immI(o), newPage[rs1]+immI(w), oldData, newData) {
				return false
			}

		case o&^uint32(rvImmS) == w&^uint32(rvImmS) && tracked&(1<<rs1) != 0 &&
			o&rvOpMask == rvStore:
			if !sameData(oldPage[rs1]+immS(o), newPage[rs1]+immS(w), oldData, newData) {
				return false
			}

		default:
			// Real change, or an AUIPC-based access this fast path
			// cannot resolve.
			return false
		}

		// Any instruction naming a page register in the rd field
		// invalidates it. Stores and branches keep immediate bits
		// there; clearing on those is spurious but only costs
		// precision.
		tracked &^= 1 << (o >> 7 & 0x1F)
	}
	// A trailing partial word must match exactly.
	for i := n; i < len(oldCode); i++ {
		if oldCode[i] != newCode[i] {
			return false
		}
	}
	return true
}

// auipcTarget computes the address produced by an AUIPC word at pc:
// pc plus the sign-extended upper immediate shifted left by 12.
func auipcTarget(word uint32, pc uint64) uint64 {
	return pc + uint64(int64(int32(word&0xFFFF_F000)))
}

// jalTarget computes the absolute target of the JAL word at offset
// off. The immediate is a signed 21-bit byte offset stored in the
// scrambled J-type bit order.
func jalTarget(word uint32, funcAddr, off uint64) uint64 {
	imm := word>>31<<20 | word>>12&0xFF<<12 | word>>20&1<<11 | word>>21&0x3FF<<1
	return funcAddr + off + uint64(int64(int32(imm<<11))>>11) // sign-extend 21 bits
}

// immI extracts the sign-extended I-type immediate of word.
func immI(word uint32) uint64 {
	return uint64(int64(int32(word)) >> 20)
}

// immS extracts the sign-extended S-type immediate of word.
func immS(word uint32) uint64 {
	return uint64(int64(int32(word))>>25<<5 | int64(word>>7&0x1F))
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

// loong64 instruction encodings, per the LoongArch reference manual.
// Register numbers occupy bits 4:0 (rd) and 9:5 (rj); instructions
// are little-endian 32-bit words.
const (
	loongBMask  = 0xFC000000
	loongB      = 0x50000000 // B offs26
	loongBL     = 0x54000000 // BL offs26
	loongPCMask = 0xFE000000
	loongPCALA  = 0x1A000000 // PCALAU12I si20 in 24:5
	// ADDI.D: si12 in 21:10.
	loongAddMask = 0xFFC00000
	loongAdd     = 0x02C00000
	// Loads and stores with a si12 offset in 21:10 (ld.*, st.*,
	// fld.*, fst.*, preld); the offset is unscaled.
	loongLdStMask = 0xFC000000
	loongLdSt     = 0x28000000
	loongSi12     = 0xFFF << 10
)

// relocOnlyLoong64 walks both bodies word by word, mirroring
// relocOnlyARM64 with PCALAU12I in the role of ADRP. Differing words
// are accepted only when the difference is confined to a field that
// relocation legitimately changes:
//
//   - B/BL displacement, when the target lies outside the function on
//     both sides and both sides resolve to the same symbol at the same
//     offset
//   - the PCALAU12I page immediate
//   - the signed 12-bit immediate of an ADDI.D or load/store based on
//     a PCALAU12I register, when the combined address resolves to the
//     same data symbol and offset on both sides
//
// Anything else — including any other use of a PCALAU12I-based
// register, whose address semantics this fast path cannot follow —
// fails, leaving the decision to full analysis.
func relocOnlyLoong64(oldCode, newCode []byte, oldAddr, newAddr uint64,
	oldSym, newSym SymLookup, oldData, newData DataLookup) bool {
	// tracked marks registers holding a PCALAU12I page address;
	// oldPage and newPage hold that page per side.
	var tracked uint32
	var oldPage, newPage [32]uint64

	n := len(oldCode) &^ 3
	for i := 0; i < n; i += 4 {
		o := binary.LittleEndian.Uint32(oldCode[i:])
		w := binary.LittleEndian.Uint32(newCode[i:])
		rj := o >> 5 & 0x1F

		switch {
		case o&loongPCMask == loongPCALA && w&loongPCMask == loongPCALA && o&0x1F == w&0x1F:
			// R0 is the hardwired zero register: a PCALAU12I writing
			// it materializes nothing, and instructions reading R0
			// afterwards read a constant zero, not the page.
			if rd := o & 0x1F; rd != 0 {
				oldPage[rd] = pcalaTarget(o, oldAddr+uint64(i))
				newPage[rd] = pcalaTarget(w, newAddr+uint64(i))
				tracked |= 1 << rd
			}
			continue

		case o&loongBMask == loongB && w&loongBMask == loongB,
			o&loongBMask == loongBL && w&loongBMask == loongBL:
			// Checked before the identical-word shortcut: with the
			// functions at different addresses, an identical
			// displacement reaches a different target, which can
			// resolve to a different symbol per side.
			oldTarget := branch26Target(o, oldAddr, uint64(i))
			newTarget := branch26Target(w, newAddr, uint64(i))
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

		case o == w && tracked&(1<<rj) == 0:
			// Identical and independent of any page register.

		case o&^uint32(loongSi12) == w&^uint32(loongSi12) && tracked&(1<<rj) != 0 &&
			o&loongAddMask == loongAdd && w&loongAddMask == loongAdd:
			if !sameData(oldPage[rj]+uint64(signExt(o>>10&0xFFF, 12)),
				newPage[rj]+uint64(signExt(w>>10&0xFFF, 12)),
				oldData, newData) {
				return false
			}

		case o&^uint32(loongSi12) == w&^uint32(loongSi12) && tracked&(1<<rj) != 0 &&
			o&loongLdStMask == loongLdSt:
			if !sameData(oldPage[rj]+uint64(signExt(o>>10&0xFFF, 12)),
				newPage[rj]+uint64(signExt(w>>10&0xFFF, 12)),
				oldData, newData) {
				return false
			}

		default:
			// Real change, or a PCALAU12I-based access this fast
			// path cannot resolve.
			return false
		}

		// Any non-PCALAU12I instruction naming a page register in
		// its rd field invalidates it. Stores name a source there;
		// over-clearing only costs precision.
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

// pcalaTarget computes the page address produced by a PCALAU12I word
// at pc.
func pcalaTarget(word uint32, pc uint64) uint64 {
	return pc&^0xFFF + uint64(signExt(word>>5&0xFFFFF, 20)<<12)
}

// branch26Target computes the absolute target of the loong64 B/BL
// word at offset off. The signed 26-bit word offset is stored split:
// its low 16 bits in instruction bits 25:10, its high 10 bits in 9:0.
func branch26Target(word uint32, funcAddr, off uint64) uint64 {
	imm := signExt(word&0x3FF<<16|word>>10&0xFFFF, 26)
	return funcAddr + off + uint64(imm*4)
}

// signExt sign-extends the low bits of v.
func signExt(v uint32, bits uint) int64 {
	shift := 64 - bits
	return int64(uint64(v)<<shift) >> shift
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
