package ixdiff

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/loov/ixdiff/internal/disasm"
)

func TestPkgOf_ExtractsPackagePaths(t *testing.T) {
	tests := []struct {
		name, want string
	}{
		{"net/url.parseHost", "net/url"},
		{"main.main", "main"},
		{"main.main.func1", "main"},
		{"github.com/x/y.(*T).m", "github.com/x/y"},
		{"github.com/x/y.(*T).m.func2", "github.com/x/y"},
		{"slices.pdqsortCmpFunc[go.shape.string]", "slices"},
		{"runtime.morestack_noctxt.abi0", "runtime"},
		{"type:.eq.sync.entry", "type:"},
		{"crosscall2", "crosscall2"},
	}
	for _, tt := range tests {
		if got := pkgOf(tt.name); got != tt.want {
			t.Errorf("pkgOf(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestOps_ExcludesBytePadding(t *testing.T) {
	insts := []disasm.Inst{
		{Op: "MOV"}, {Op: "RET"}, {Op: "BYTE"}, {Op: "BYTE"},
	}
	if got := ops(insts); len(got) != 2 {
		t.Errorf("ops = %v, want BYTE excluded", got)
	}
	if got := countInsts(insts); got != 2 {
		t.Errorf("countInsts = %d, want 2", got)
	}
}

func TestOpCount_DeltaAndAdd(t *testing.T) {
	old := countOps([]string{"CALL", "CALL", "MOV", "RET"})
	new := countOps([]string{"CALL", "MOV", "MOV", "ADD", "RET"})

	want := OpCount{"CALL": -1, "MOV": 1, "ADD": 1}
	if diff := cmp.Diff(want, old.Delta(new)); diff != "" {
		t.Errorf("Delta mismatch (-want +got):\n%s", diff)
	}

	total := OpCount{}
	total.Add(old.Delta(new))
	total.Add(OpCount{"CALL": 5})
	if got := total["CALL"]; got != 4 {
		t.Errorf("accumulated CALL = %d, want 4", got)
	}
	if got := old.Total(); got != 4 {
		t.Errorf("Total = %d, want 4", got)
	}
	total.Add(OpCount{"MOV": -1, "ADD": -1, "CALL": -4})
	total.Compact()
	if len(total) != 0 {
		t.Errorf("Compact left %v, want empty", total)
	}
}
