package main

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/loov/ixdiff/internal/fndiff"
)

// mkAnalysis builds an analysis whose old side is olds and new side is
// news, with synthetic 4-byte-spaced addresses starting at 0x100 (old)
// and 0x200 (new).
func mkAnalysis(olds, news []string) *analysis {
	a := &analysis{
		pair:  &fndiff.Pair{Name: "f", State: fndiff.StateChanged},
		edits: fndiff.Diff(olds, news),
	}
	for i := range olds {
		a.oldAddrs = append(a.oldAddrs, uint64(0x100+4*i))
	}
	for i := range news {
		a.newAddrs = append(a.newAddrs, uint64(0x200+4*i))
	}
	return a
}

func TestMatchFuncs_Resolution(t *testing.T) {
	pairs := []*fndiff.Pair{
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

func TestDiffLines_ResolvesAddressesPerSide(t *testing.T) {
	a := mkAnalysis(
		[]string{"one", "two", "three"},
		[]string{"one", "TWO", "three"},
	)
	got := diffLines(a)
	want := []diffLine{
		{fndiff.OpEqual, 0x100, 0x200, "one"},
		{fndiff.OpDelete, 0x104, 0, "two"},
		{fndiff.OpInsert, 0, 0x204, "TWO"},
		{fndiff.OpEqual, 0x108, 0x208, "three"},
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(diffLine{})); diff != "" {
		t.Errorf("diffLines mismatch (-want +got):\n%s", diff)
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

	got := hunks(diffLines(mkAnalysis(olds, news)))
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

func TestHunks_ShortEqualRunStaysInOneHunk(t *testing.T) {
	olds := []string{"a", "m", "n", "z"}
	news := []string{"A", "m", "n", "Z"}
	got := hunks(diffLines(mkAnalysis(olds, news)))
	if len(got) != 1 {
		t.Fatalf("got %d hunks, want 1", len(got))
	}
	if len(got[0]) != 6 {
		t.Errorf("hunk has %d lines, want 6", len(got[0]))
	}
}
