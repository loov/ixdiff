package fndiff

import (
	"testing"

	"github.com/loov/ixdiff/internal/objfile"
)

func TestCanonicalName_StripsRenumberedParts(t *testing.T) {
	tests := []struct {
		name, want string
	}{
		{"main.f.func1", "main.f.func"},
		{"main.f.func2", "main.f.func"},
		{"main.f.func1.func3", "main.f.func.func"},
		{"main.f.gowrap12", "main.f.gowrap"},
		{"main.f.deferwrap1", "main.f.deferwrap"},
		{"slices.Sort[go.shape.int]", "slices.Sort"},
		{"main.plain", "main.plain"},
	}
	for _, tt := range tests {
		if got := canonicalName(tt.name); got != tt.want {
			t.Errorf("canonicalName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestMatchRenames_PairsByCanonicalNameAndSimilarity(t *testing.T) {
	mk := func(name string, state State) *Pair {
		p := &Pair{Name: name, State: state}
		fn := &objfile.Func{Name: name}
		switch state {
		case StateAdded:
			p.New = fn
		case StateRemoved:
			p.Old = fn
		}
		return p
	}
	pairs := []*Pair{
		mk("main.f.func2", StateAdded),   // canonical match with .func1
		mk("main.f.func1", StateRemoved),
		mk("main.newName", StateAdded),   // similarity match
		mk("main.oldName", StateRemoved),
		mk("main.reallyGone", StateRemoved), // stays removed
		{Name: "main.same", State: StateIdentical},
	}
	similar := func(old, new *objfile.Func) bool {
		return old.Name == "main.oldName" && new.Name == "main.newName"
	}

	got := MatchRenames(pairs, similar)

	byName := map[string]*Pair{}
	for _, p := range got {
		byName[p.Name] = p
	}
	if p := byName["main.f.func2"]; p == nil || p.State != StateChanged || p.RenamedFrom != "main.f.func1" {
		t.Errorf("closure renumbering not paired: %+v", p)
	}
	if p := byName["main.newName"]; p == nil || p.State != StateChanged || p.RenamedFrom != "main.oldName" {
		t.Errorf("similarity rename not paired: %+v", p)
	}
	if p := byName["main.reallyGone"]; p == nil || p.State != StateRemoved {
		t.Errorf("unmatched removal should stay removed: %+v", p)
	}
	if _, ok := byName["main.f.func1"]; ok {
		t.Error("removed side of a rename still present")
	}
	if len(got) != 4 {
		t.Errorf("got %d pairs, want 4: %+v", len(got), got)
	}
}
