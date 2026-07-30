package disasm

import (
	"bytes"

	"golang.org/x/arch/x86/x86asm"
)

// relocOnlyAMD64 decodes both bodies in lockstep and accepts a
// difference only when the decoded instructions are identical except
// for a relocation-bearing field:
//
//   - a PC-relative branch/call displacement whose targets resolve to
//     the same symbol at the same offset on both sides (equal
//     displacements still resolve, since equal bytes at different
//     addresses can reach different symbols)
//   - a RIP-relative memory displacement whose targets render
//     identically under the data-reference rules
//
// Differing immediates, registers, or opcodes fail, as does anything
// that does not decode; full analysis then decides.
func relocOnlyAMD64(oldCode, newCode []byte, oldAddr, newAddr uint64,
	oldSym, newSym SymLookup, oldData, newData DataLookup) bool {
	off := 0
	for off < len(oldCode) {
		oi, oerr := x86asm.Decode(oldCode[off:], 64)
		ni, nerr := x86asm.Decode(newCode[off:], 64)
		if oerr != nil || nerr != nil || oi.Op == 0 || ni.Op == 0 {
			// Undecodable tail (alignment padding): exact match only.
			return bytes.Equal(oldCode[off:], newCode[off:])
		}
		if oi.Op != ni.Op || oi.Len != ni.Len || oi.Prefix != ni.Prefix {
			return false
		}

		for k := range oi.Args {
			oa, na := oi.Args[k], ni.Args[k]
			if oa == nil || na == nil {
				if oa != na {
					return false
				}
				break
			}
			switch oarg := oa.(type) {
			case x86asm.Rel:
				narg, ok := na.(x86asm.Rel)
				if !ok {
					return false
				}
				end := uint64(off + oi.Len)
				oldTarget := oldAddr + end + uint64(int64(oarg))
				newTarget := newAddr + end + uint64(int64(narg))
				intraOld := within(oldTarget, oldAddr, uint64(len(oldCode)))
				intraNew := within(newTarget, newAddr, uint64(len(oldCode)))
				if intraOld || intraNew {
					// Intra-function branches must agree exactly.
					if oarg != narg || !intraOld || !intraNew {
						return false
					}
					continue
				}
				oldName, oldBase := oldSym(oldTarget)
				newName, newBase := newSym(newTarget)
				if oldName == "" || oldName != newName ||
					oldTarget-oldBase != newTarget-newBase {
					return false // different callee
				}

			case x86asm.Mem:
				narg, ok := na.(x86asm.Mem)
				if !ok {
					return false
				}
				if oarg.Base == x86asm.RIP && narg.Base == x86asm.RIP {
					stripped := oarg
					stripped.Disp = narg.Disp
					if stripped != narg {
						return false
					}
					end := uint64(off + oi.Len)
					if !sameData(oldAddr+end+uint64(oarg.Disp), newAddr+end+uint64(narg.Disp),
						oldData, newData) {
						return false
					}
					continue
				}
				if oarg != narg {
					return false
				}

			default:
				if oa != na {
					return false
				}
			}
		}
		off += oi.Len
	}
	return true
}
