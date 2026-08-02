package fndiff_test

import (
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
	var gotA, gotB []string
	for _, e := range fndiff.Diff(a, b) {
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
