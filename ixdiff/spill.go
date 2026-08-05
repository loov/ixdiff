package ixdiff

import (
	"strings"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/objfile"
)

// countSpills counts the instructions of insts with a stack-pointer-
// relative memory operand. The Go compiler addresses spill slots off
// the stack pointer, so this captures register spills and reloads —
// but also stack-passed call arguments and register saves, which use
// the same addressing. The absolute count is therefore a heuristic;
// the delta between two builds of the same code isolates the code
// generation change.
func countSpills(arch objfile.Arch, insts []disasm.Inst) int {
	n := 0
	for _, in := range insts {
		if in.Op == "BYTE" {
			continue
		}
		_, rest, ok := strings.Cut(in.Text, " ")
		if !ok {
			continue
		}
		// ppc64 GoSyntax joins operands with a bare comma, the other
		// architectures with comma-space; strip the optional space.
		for arg := range strings.SplitSeq(rest, ",") {
			if disasm.IsStackRef(arch, strings.TrimPrefix(arg, " ")) {
				n++
				break
			}
		}
	}
	return n
}
