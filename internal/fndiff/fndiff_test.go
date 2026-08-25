package fndiff_test

import (
	"testing"

	"github.com/loov/disasm/objfile"
	"github.com/loov/ixdiff/internal/fndiff"
	"github.com/loov/ixdiff/internal/testbin"
)

func open(t *testing.T, cfg testbin.Config) *objfile.Binary {
	t.Helper()
	bin, err := objfile.Open(testbin.Build(t, cfg))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return bin
}

func TestCompare_ClassifiesPairs(t *testing.T) {
	plain := open(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	padded := open(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", Tags: "pad"})

	byName := map[string]*fndiff.Pair{}
	for _, p := range fndiff.Compare(plain, padded) {
		byName[p.Name] = p
	}

	pad := byName["main.aaaPad"]
	if pad == nil || pad.State != fndiff.StateAdded {
		t.Errorf("main.aaaPad = %v, want added", pad)
	}
	if pad != nil && pad.SizeDelta() != int64(pad.New.Size) {
		t.Errorf("added SizeDelta = %d, want %d", pad.SizeDelta(), pad.New.Size)
	}

	// The reverse comparison must see the same function as removed.
	for _, p := range fndiff.Compare(padded, plain) {
		if p.Name == "main.aaaPad" {
			if p.State != fndiff.StateRemoved {
				t.Errorf("reverse main.aaaPad state = %v, want removed", p.State)
			}
			if p.SizeDelta() != -int64(p.Old.Size) {
				t.Errorf("removed SizeDelta = %d, want %d", p.SizeDelta(), -int64(p.Old.Size))
			}
		}
	}

	states := map[fndiff.State]int{}
	for _, p := range fndiff.Compare(plain, padded) {
		states[p.State]++
	}
	if states[fndiff.StateIdentical] == 0 {
		t.Error("no identical functions between near-identical builds")
	}
	if states[fndiff.StateUnknown] > 0 {
		t.Errorf("%d pairs left unclassified", states[fndiff.StateUnknown])
	}
}

func TestCompare_SelfComparisonIsAllIdentical(t *testing.T) {
	bin := open(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	for _, p := range fndiff.Compare(bin, bin) {
		if p.State != fndiff.StateIdentical {
			t.Fatalf("%s = %v, want identical", p.Name, p.State)
		}
	}
}
