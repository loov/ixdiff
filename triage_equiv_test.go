package main

import (
	"slices"
	"testing"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/fndiff"
	"github.com/loov/ixdiff/internal/objfile"
	"github.com/loov/ixdiff/internal/testbin"
)

// TestRelocOnly_NeverContradictsFullAnalysis is the safety property of
// the fast triage: whenever RelocOnly claims a pair is relocation-only
// noise, the full normalize-and-align path must agree. The reverse —
// the fast path failing to recognize noise — is only a missed speedup
// and is allowed. This harness caught the zero-displacement <lo12>
// masking bug.
func TestRelocOnly_NeverContradictsFullAnalysis(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		for _, variant := range []testbin.Config{
			{GOOS: "linux", GOARCH: arch, GCFlags: "-l"},
			{GOOS: "linux", GOARCH: arch, Tags: "pad"},
		} {
			t.Run(arch+"/"+variant.GCFlags+variant.Tags, func(t *testing.T) {
				base, err := objfile.Open(testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: arch}))
				if err != nil {
					t.Fatalf("Open base: %v", err)
				}
				other, err := objfile.Open(testbin.Build(t, variant))
				if err != nil {
					t.Fatalf("Open variant: %v", err)
				}
				checkTriageEquivalence(t, base, other)
			})
		}
	}
}

// checkTriageEquivalence verifies the property over every changed pair
// of two binaries and reports how often the fast path fired.
func checkTriageEquivalence(t *testing.T, old, new *objfile.Binary) {
	t.Helper()
	oldLookup, newLookup := disasm.Lookup(old), disasm.Lookup(new)
	fast, contradictions := 0, 0
	for _, p := range fndiff.Compare(old, new) {
		if p.State != fndiff.StateChanged {
			continue
		}
		if !disasm.RelocOnly(old.Arch, p.Old.Code(), p.New.Code(),
			p.Old.Addr, p.New.Addr, oldLookup, newLookup) {
			continue
		}
		fast++

		oldInsts, err := disasm.Decode(old.Arch, p.Old.Code(), p.Old.Addr, oldLookup)
		if err != nil {
			t.Fatalf("Decode old %s: %v", p.Name, err)
		}
		newInsts, err := disasm.Decode(new.Arch, p.New.Code(), p.New.Addr, newLookup)
		if err != nil {
			t.Fatalf("Decode new %s: %v", p.Name, err)
		}
		oldLines, newLines := alignLabels(
			disasm.NormalizeLines(p.Old.Name, oldInsts, disasm.Options{IsAddr: old.Contains}),
			disasm.NormalizeLines(p.New.Name, newInsts, disasm.Options{IsAddr: new.Contains}))
		if !slices.Equal(oldLines, newLines) {
			contradictions++
			for i := range oldLines {
				if oldLines[i] != newLines[i] {
					t.Errorf("%s: fast path claims noise, full path disagrees at line %d:\n  old %q\n  new %q",
						p.Name, i, oldLines[i], newLines[i])
					break
				}
			}
		}
	}
	t.Logf("fast path fired on %d changed pairs, %d contradictions", fast, contradictions)
}
