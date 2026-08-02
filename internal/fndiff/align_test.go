package fndiff_test

import (
	"testing"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/fndiff"
)

// line is a shorthand for a disasm.Line without a branch.
func line(text string) disasm.Line { return disasm.Line{Text: text, Target: -1} }

// branch is a shorthand for a branch line; the label slot uses the
// same internal marker as disasm.NormalizeLines ("\x01").
func branch(op string, target int) disasm.Line {
	return disasm.Line{Text: op + " \x01", Target: target}
}

func TestAlignLabels_UnchangedBranchesKeepLabels(t *testing.T) {
	// The new side inserts an early branch and its target; the later
	// branch to RET is structurally unchanged and must render with
	// the same label on both sides.
	old := []disasm.Line{
		branch("JBE", 2),
		line("MOVL $0x1, DI"),
		line("RET"),
	}
	new := []disasm.Line{
		branch("JE", 1),
		line("NOPL"), // new branch target
		branch("JBE", 4),
		line("MOVL $0x1, DI"),
		line("RET"),
	}
	oldLines, newLines := fndiff.AlignLabels(old, new)

	if oldLines[0] != newLines[2] {
		t.Errorf("unchanged branch renders differently: %q vs %q", oldLines[0], newLines[2])
	}
	if oldLines[1] != newLines[3] || oldLines[2] != newLines[4] {
		t.Errorf("aligned non-branch lines differ:\nold %v\nnew %v", oldLines, newLines)
	}
}

func TestAlignLabels_RetargetedBranchDiffs(t *testing.T) {
	// Same instruction sequence, but the branch jumps to a different
	// aligned instruction: labels must differ so the diff surfaces it.
	old := []disasm.Line{
		branch("JBE", 1),
		line("MOVL $0x1, DI"),
		line("RET"),
	}
	new := []disasm.Line{
		branch("JBE", 2),
		line("MOVL $0x1, DI"),
		line("RET"),
	}
	oldLines, newLines := fndiff.AlignLabels(old, new)
	if oldLines[0] == newLines[0] {
		t.Errorf("retargeted branch renders identically: %q", oldLines[0])
	}
}
