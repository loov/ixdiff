package fndiff_test

import (
	"runtime"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/loov/ixdiff/internal/fndiff"
)

func TestDiff_EditScripts(t *testing.T) {
	eq := func(s string) fndiff.Edit { return fndiff.Edit{Op: fndiff.OpEqual, Text: s} }
	del := func(s string) fndiff.Edit { return fndiff.Edit{Op: fndiff.OpDelete, Text: s} }
	ins := func(s string) fndiff.Edit { return fndiff.Edit{Op: fndiff.OpInsert, Text: s} }

	tests := []struct {
		name string
		a, b []string
		want []fndiff.Edit
	}{
		{
			name: "equal",
			a:    []string{"x", "y"},
			b:    []string{"x", "y"},
			want: []fndiff.Edit{eq("x"), eq("y")},
		},
		{
			name: "insert middle",
			a:    []string{"x", "z"},
			b:    []string{"x", "y", "z"},
			want: []fndiff.Edit{eq("x"), ins("y"), eq("z")},
		},
		{
			name: "delete middle",
			a:    []string{"x", "y", "z"},
			b:    []string{"x", "z"},
			want: []fndiff.Edit{eq("x"), del("y"), eq("z")},
		},
		{
			name: "replace",
			a:    []string{"x", "old", "z"},
			b:    []string{"x", "new", "z"},
			want: []fndiff.Edit{eq("x"), del("old"), ins("new"), eq("z")},
		},
		{
			name: "empty old",
			a:    nil,
			b:    []string{"x"},
			want: []fndiff.Edit{ins("x")},
		},
		{
			name: "empty new",
			a:    []string{"x"},
			b:    nil,
			want: []fndiff.Edit{del("x")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fndiff.Diff(tt.a, tt.b)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Diff mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDiff_Reconstructs checks the edit-script invariants: keeping
// equals and deletes rebuilds a, keeping equals and inserts rebuilds b.
func TestDiff_Reconstructs(t *testing.T) {
	a := []string{"m", "a", "c", "x", "b", "n", "n", "z"}
	b := []string{"m", "z", "x", "b", "c", "n", "y"}
	checkReconstructs(t, a, b, fndiff.Diff(a, b))
}

// TestDiff_LargeFunctionBoundedMemory diffs functions far beyond the
// exact-table limit whose first and last lines differ, so trimming
// cannot shrink the region. An unbounded LCS table would need 800 MB.
func TestDiff_LargeFunctionBoundedMemory(t *testing.T) {
	const n = 10000
	a, b := make([]string, n), make([]string, n)
	for i := range a {
		a[i] = "MOVQ $" + strconv.Itoa(i) + ", AX"
		b[i] = a[i]
	}
	a[0], b[n-1] = "old", "new"
	b[n/2] = "changed"

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	edits := fndiff.Diff(a, b)
	runtime.ReadMemStats(&after)

	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
		t.Errorf("Diff allocated %d MB, want at most 64 MB", alloc>>20)
	}
	checkReconstructs(t, a, b, edits)
	equal := 0
	for _, e := range edits {
		if e.Op == fndiff.OpEqual {
			equal++
		}
	}
	if want := n - 3; equal != want {
		t.Errorf("Diff kept %d equal lines, want %d", equal, want)
	}
}

// TestDiff_LargeWithoutUniqueLines covers a large region with no
// anchor lines, which falls back to a full replacement.
func TestDiff_LargeWithoutUniqueLines(t *testing.T) {
	const n = 5000
	a, b := make([]string, n), make([]string, n)
	for i := range a {
		a[i] = "NOP"
		b[i] = "RET"
	}
	checkReconstructs(t, a, b, fndiff.Diff(a, b))
}

func TestLongestIncreasing(t *testing.T) {
	tests := []struct {
		name   string
		values []int
		want   []int
	}{
		{name: "empty", values: nil, want: nil},
		{name: "sorted", values: []int{1, 2, 3}, want: []int{0, 1, 2}},
		{name: "one moved to front", values: []int{3, 0, 1, 2}, want: []int{1, 2, 3}},
		{name: "one moved to back", values: []int{1, 2, 3, 0}, want: []int{0, 1, 2}},
		{name: "reversed", values: []int{2, 1, 0}, want: []int{2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, fndiff.LongestIncreasing(tt.values)); diff != "" {
				t.Errorf("LongestIncreasing(%v) mismatch (-want +got):\n%s", tt.values, diff)
			}
		})
	}
}

// checkReconstructs verifies that keeping equals and deletes rebuilds
// a, and keeping equals and inserts rebuilds b.
func checkReconstructs(t *testing.T, a, b []string, edits []fndiff.Edit) {
	t.Helper()
	var gotA, gotB []string
	for _, e := range edits {
		if e.Op != fndiff.OpInsert {
			gotA = append(gotA, e.Text)
		}
		if e.Op != fndiff.OpDelete {
			gotB = append(gotB, e.Text)
		}
	}
	if diff := cmp.Diff(a, gotA); diff != "" {
		t.Errorf("old side not reconstructed (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(b, gotB); diff != "" {
		t.Errorf("new side not reconstructed (-want +got):\n%s", diff)
	}
}
