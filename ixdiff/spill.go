package ixdiff

import (
	disasmanalysis "github.com/loov/disasm/analysis"

	"github.com/loov/ixdiff/internal/norm"
)

// countSpills weighs the stack accesses of insts two ways: spills
// counts the registers moved to or from the stack, slots the 8-byte
// stack slots touched. See [disasmanalysis.StackAccesses] for what counts.
//
// Either absolute count is a heuristic; the delta between two builds
// of the same code isolates the code generation change.
func countSpills(arch string, insts []norm.Inst) (spills, slots int) {
	for _, a := range disasmanalysis.StackAccesses(arch, insts) {
		spills += a.Regs
		slots += a.Slots
	}
	return spills, slots
}
