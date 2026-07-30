package main

import "testing"

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
