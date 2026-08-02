package main

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/loov/ixdiff/internal/fndiff"
	"github.com/loov/ixdiff/ixdiff"
)

// mkLines builds the diff lines of a change whose old side is olds and
// new side is news, with synthetic 4-byte-spaced addresses starting at
// 0x100 (old) and 0x200 (new).
func mkLines(olds, news []string) []ixdiff.Line {
	var oldAddrs, newAddrs []uint64
	for i := range olds {
		oldAddrs = append(oldAddrs, uint64(0x100+4*i))
	}
	for i := range news {
		newAddrs = append(newAddrs, uint64(0x200+4*i))
	}
	return resolveLines(fndiff.Diff(olds, news), oldAddrs, newAddrs)
}

func TestMatchFuncs_Resolution(t *testing.T) {
	pairs := []ixdiff.Pair{
		{Name: "main.sum"},
		{Name: "main.summary"},
		{Name: "runtime.mallocgc"},
	}

	t.Run("exact beats substring", func(t *testing.T) {
		got, err := matchFuncs(pairs, "main.sum")
		if err != nil || len(got) != 1 || got[0].Name != "main.sum" {
			t.Errorf("got %v, %v; want exactly main.sum", got, err)
		}
	})

	t.Run("unique substring resolves", func(t *testing.T) {
		got, err := matchFuncs(pairs, "mallocgc")
		if err != nil || len(got) != 1 || got[0].Name != "runtime.mallocgc" {
			t.Errorf("got %v, %v; want runtime.mallocgc", got, err)
		}
	})

	t.Run("ambiguous substring lists all", func(t *testing.T) {
		got, err := matchFuncs(pairs, "main.su")
		if err != nil || len(got) != 2 {
			t.Errorf("got %v, %v; want both main.su matches", got, err)
		}
	})

	t.Run("miss suggests closest", func(t *testing.T) {
		_, err := matchFuncs(pairs, "main.sun")
		if err == nil || !strings.Contains(err.Error(), "main.sum") {
			t.Errorf("err = %v, want suggestion of main.sum", err)
		}
	})
}

func TestResolveLines_ResolvesAddressesPerSide(t *testing.T) {
	got := mkLines(
		[]string{"one", "two", "three"},
		[]string{"one", "TWO", "three"},
	)
	want := []ixdiff.Line{
		{Op: ixdiff.Equal, OldAddr: 0x100, NewAddr: 0x200, Text: "one"},
		{Op: ixdiff.Delete, OldAddr: 0x104, Text: "two"},
		{Op: ixdiff.Insert, NewAddr: 0x204, Text: "TWO"},
		{Op: ixdiff.Equal, OldAddr: 0x108, NewAddr: 0x208, Text: "three"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("resolveLines mismatch (-want +got):\n%s", diff)
	}
}

func TestHunks_SplitsOnLongEqualRuns(t *testing.T) {
	// change, 10 equal lines, change: must split into two hunks with
	// three lines of context on each side of the gap.
	olds := []string{"a"}
	news := []string{"A"}
	for i := range 10 {
		mid := string(rune('m' + i))
		olds = append(olds, mid)
		news = append(news, mid)
	}
	olds = append(olds, "z")
	news = append(news, "Z")

	got := hunks(mkLines(olds, news))
	if len(got) != 2 {
		t.Fatalf("got %d hunks, want 2", len(got))
	}
	// First hunk: -a +A plus 3 trailing context lines.
	if len(got[0]) != 5 {
		t.Errorf("first hunk has %d lines, want 5", len(got[0]))
	}
	// Second hunk: 3 leading context lines plus -z +Z.
	if len(got[1]) != 5 {
		t.Errorf("second hunk has %d lines, want 5", len(got[1]))
	}
}

func TestEmphasizeDiff_MarksOnlyChangedOperands(t *testing.T) {
	oldText, newText, ok := ansi.emphasizeDiff(
		"MOVQ   R11, 0x390(SP)",
		"MOVQ   R11, 0x328(SP)")
	if !ok {
		t.Fatal("expected same-shape lines to emphasize")
	}
	wantOld := "MOVQ   R11, " + ansi.emph + "0x390" + ansi.unemph + "(SP)"
	wantNew := "MOVQ   R11, " + ansi.emph + "0x328" + ansi.unemph + "(SP)"
	if oldText != wantOld || newText != wantNew {
		t.Errorf("got:\n%q\n%q\nwant:\n%q\n%q", oldText, newText, wantOld, wantNew)
	}

	// Within an operand only the differing sub-token is marked: a
	// changed base register leaves the shared offset unemphasized.
	oldText, newText, ok = ansi.emphasizeDiff("MOVD 8(R6), R6", "MOVD 8(R7), R7")
	if !ok {
		t.Fatal("expected same-shape lines to emphasize")
	}
	wantOld = "MOVD 8(" + ansi.emph + "R6" + ansi.unemph + "), " + ansi.emph + "R6" + ansi.unemph
	wantNew = "MOVD 8(" + ansi.emph + "R7" + ansi.unemph + "), " + ansi.emph + "R7" + ansi.unemph
	if oldText != wantOld || newText != wantNew {
		t.Errorf("got:\n%q\n%q\nwant:\n%q\n%q", oldText, newText, wantOld, wantNew)
	}

	// Operands with different punctuation shapes are marked whole.
	oldText, newText, ok = ansi.emphasizeDiff("MOVD 8(R6), R1", "MOVD $8, R1")
	if !ok {
		t.Fatal("expected same-shape lines to emphasize")
	}
	wantOld = "MOVD " + ansi.emph + "8(R6)" + ansi.unemph + ", R1"
	wantNew = "MOVD " + ansi.emph + "$8" + ansi.unemph + ", R1"
	if oldText != wantOld || newText != wantNew {
		t.Errorf("got:\n%q\n%q\nwant:\n%q\n%q", oldText, newText, wantOld, wantNew)
	}

	if _, _, ok := ansi.emphasizeDiff("MOVQ R11, R12", "LEAQ R11, R12"); ok {
		t.Error("different mnemonics must fall back to whole-line coloring")
	}
	if _, _, ok := ansi.emphasizeDiff("CALL a(SB)", "MOVQ R11, R12"); ok {
		t.Error("different operand counts must fall back to whole-line coloring")
	}
	if _, _, ok := (palette{}).emphasizeDiff("MOVQ R11, A", "MOVQ R11, B"); ok {
		t.Error("plain palette must not emphasize")
	}
}

func TestAlignOps_PadsMnemonicsToCommonColumn(t *testing.T) {
	got := alignOps([]string{
		"MOVQ R11, 0x390(SP)",
		"CALL runtime.makeslice(SB)",
		"MOVUPS X15, 0(AX)",
		"RET",
	})
	want := []string{
		"MOVQ   R11, 0x390(SP)",
		"CALL   runtime.makeslice(SB)",
		"MOVUPS X15, 0(AX)",
		"RET",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("alignOps mismatch (-want +got):\n%s", diff)
	}
}

func TestSideRows_PairsReplacements(t *testing.T) {
	rows := sideRows(mkLines(
		[]string{"same", "del1", "del2", "tail"},
		[]string{"same", "ins1", "tail"},
	))
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want 4", len(rows))
	}
	if rows[0].old == nil || rows[0].new == nil || rows[0].old.Text != "same" {
		t.Errorf("row 0 should pair the equal line, got %+v", rows[0])
	}
	if rows[1].old == nil || rows[1].new == nil ||
		rows[1].old.Text != "del1" || rows[1].new.Text != "ins1" {
		t.Errorf("row 1 should pair del1 with ins1, got %+v", rows[1])
	}
	if rows[2].old == nil || rows[2].new != nil || rows[2].old.Text != "del2" {
		t.Errorf("row 2 should be delete-only, got %+v", rows[2])
	}
}

func TestHunks_ShortEqualRunStaysInOneHunk(t *testing.T) {
	olds := []string{"a", "m", "n", "z"}
	news := []string{"A", "m", "n", "Z"}
	got := hunks(mkLines(olds, news))
	if len(got) != 1 {
		t.Fatalf("got %d hunks, want 1", len(got))
	}
	if len(got[0]) != 6 {
		t.Errorf("hunk has %d lines, want 6", len(got[0]))
	}
}
