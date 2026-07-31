package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/loov/ixdiff/internal/disasm"
)

func mkBlock(addr uint64, lines ...string) block {
	b := block{lines: lines}
	for i := range lines {
		b.addrs = append(b.addrs, addr+uint64(4*i))
	}
	return b
}

func TestSplitBlocks_CutsAtLeadersAndTransfers(t *testing.T) {
	lines := []string{"CMP R0, R1", "BEQ L1", "MOV $1, R0", "JMP L2", "MOV $2, R0", "RET"}
	addrs := []uint64{0x100, 0x104, 0x108, 0x10c, 0x110, 0x114}
	// index 4 is a branch target (L1); BEQ, JMP, and RET end blocks.
	got := splitBlocks(lines, addrs,
		map[int]bool{0: true, 4: true},
		map[int]bool{1: true, 3: true, 5: true})
	want := []block{
		mkBlock(0x100, "CMP R0, R1", "BEQ L1"),
		mkBlock(0x108, "MOV $1, R0", "JMP L2"),
		mkBlock(0x110, "MOV $2, R0", "RET"),
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(block{})); diff != "" {
		t.Errorf("splitBlocks mismatch (-want +got):\n%s", diff)
	}
}

// TestBlockEnds_UsesRenderedMnemonic checks that terminators are
// recognized by the rendered text, not the raw decoder Op: riscv64
// returns decode as JALR but render as RET, and wasm ops are lowercase.
func TestBlockEnds_UsesRenderedMnemonic(t *testing.T) {
	nl := []disasm.Line{
		{Text: "ADD X10, X11", Target: -1},
		{Text: "BEQ X10, X0, \x01", Target: 3}, // conditional with label target
		{Text: "RET", Target: -1},              // riscv64 return, raw Op JALR
		{Text: "i32.const 1", Target: -1},
		{Text: "return", Target: -1}, // wasm return
	}
	insts := []disasm.Inst{
		{Op: "ADD", Text: "ADD X10, X11"},
		{Op: "BEQ", Text: "BEQ X10, X0, 2(PC)"},
		{Op: "JALR", Text: "RET"},
		{Op: "i32.const", Text: "i32.const 1"},
		{Op: "return", Text: "return"},
	}
	got := blockEnds(nl, insts)
	want := map[int]bool{1: true, 2: true, 4: true}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("blockEnds mismatch (-want +got):\n%s", diff)
	}
}

func TestMatchBlocks_ReportsMovesAndLeftovers(t *testing.T) {
	a := mkBlock(0x100, "alpha", "JMP L1")
	b := mkBlock(0x108, "beta", "RET")
	c := mkBlock(0x110, "gamma", "RET")

	// New side swaps beta behind gamma and replaces alpha's body.
	aChanged := mkBlock(0x200, "ALPHA", "JMP L1")
	cNew := mkBlock(0x208, "gamma", "RET")
	bNew := mkBlock(0x210, "beta", "RET")

	moves, restOld, restNew := matchBlocks(
		[]block{a, b, c},
		[]block{aChanged, cNew, bNew},
	)

	if len(moves) != 1 || moves[0].oldAddr != 0x108 || moves[0].newAddr != 0x210 || moves[0].insts != 2 {
		t.Errorf("moves = %+v, want beta moved 0x108 -> 0x210", moves)
	}
	if diff := cmp.Diff(a.lines, restOld.lines); diff != "" {
		t.Errorf("restOld should be alpha's lines (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(aChanged.lines, restNew.lines); diff != "" {
		t.Errorf("restNew should be ALPHA's lines (-want +got):\n%s", diff)
	}
}

func TestMatchBlocks_IdenticalSidesNoOutput(t *testing.T) {
	a := mkBlock(0x100, "alpha", "RET")
	b := mkBlock(0x108, "beta", "RET")
	moves, restOld, restNew := matchBlocks([]block{a, b}, []block{a, b})
	if len(moves) != 0 || len(restOld.lines) != 0 || len(restNew.lines) != 0 {
		t.Errorf("identical sides produced output: moves=%v restOld=%v restNew=%v",
			moves, restOld.lines, restNew.lines)
	}
}
