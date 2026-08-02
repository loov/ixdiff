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
	// Only arches with a RelocOnly fast path (see the switch in
	// internal/disasm/reloc.go). s390x, ppc64, and ppc64le have none,
	// so running them here would assert nothing.
	for _, arch := range []string{"amd64", "arm64", "arm", "riscv64", "loong64", "386"} {
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
				if fired := checkTriageEquivalence(t, base, other); fired == 0 {
					t.Error("fast path never fired, harness is vacuous for this arch")
				}
			})
		}
	}
}

// TestWasm_PadShiftIsPureNoise verifies wasm normalization over the
// whole binary: a padding function shifts every function index, type
// index, PC constant, and data offset, so every byte-changed pair must
// normalize back to identical lines. Any pair that does not means an
// unstable operand kind leaked through.
func TestWasm_PadShiftIsPureNoise(t *testing.T) {
	old, err := objfile.Open(testbin.Build(t, testbin.Config{GOOS: "wasip1", GOARCH: "wasm"}))
	if err != nil {
		t.Fatalf("Open base: %v", err)
	}
	new, err := objfile.Open(testbin.Build(t, testbin.Config{GOOS: "wasip1", GOARCH: "wasm", Tags: "pad"}))
	if err != nil {
		t.Fatalf("Open pad: %v", err)
	}
	oldLookup, newLookup := disasm.Lookup(old), disasm.Lookup(new)
	changed, noisy := 0, 0
	for _, p := range fndiff.Compare(old, new) {
		if p.State != fndiff.StateChanged {
			continue
		}
		changed++
		oldInsts, err := disasm.Decode(old.Arch, p.Old.Code(), p.Old.Addr, oldLookup)
		if err != nil {
			t.Fatalf("Decode old %s: %v", p.Name, err)
		}
		newInsts, err := disasm.Decode(new.Arch, p.New.Code(), p.New.Addr, newLookup)
		if err != nil {
			t.Fatalf("Decode new %s: %v", p.Name, err)
		}
		oldLines, newLines := fndiff.AlignLabels(
			disasm.NormalizeLines(p.Old.Name, oldInsts, disasm.Options{IsAddr: old.Contains}),
			disasm.NormalizeLines(p.New.Name, newInsts, disasm.Options{IsAddr: new.Contains}))
		if slices.Equal(oldLines, newLines) {
			noisy++
			continue
		}
		reportLineDiff(t, p.Name+": normalized lines differ", oldLines, newLines)
	}
	if changed == 0 {
		t.Fatal("padding did not change any pair, test would be vacuous")
	}
	t.Logf("%d changed pairs, %d pure noise", changed, noisy)
}

// checkTriageEquivalence verifies the property over every changed pair
// of two binaries and returns how often the fast path fired.
func checkTriageEquivalence(t *testing.T, old, new *objfile.Binary) int {
	t.Helper()
	oldLookup, newLookup := disasm.Lookup(old), disasm.Lookup(new)
	fast, contradictions := 0, 0
	for _, p := range fndiff.Compare(old, new) {
		if p.State != fndiff.StateChanged {
			continue
		}
		if !disasm.RelocOnly(old.Arch, p.Old.Code(), p.New.Code(),
			p.Old.Addr, p.New.Addr, oldLookup, newLookup, old.DataSym, new.DataSym) {
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
		oldLines, newLines := fndiff.AlignLabels(
			disasm.NormalizeLines(p.Old.Name, oldInsts, disasm.Options{IsAddr: old.Contains, DataSym: old.DataSym}),
			disasm.NormalizeLines(p.New.Name, newInsts, disasm.Options{IsAddr: new.Contains, DataSym: new.DataSym}))
		if !slices.Equal(oldLines, newLines) {
			contradictions++
			reportLineDiff(t, p.Name+": fast path claims noise, full path disagrees", oldLines, newLines)
		}
	}
	t.Logf("fast path fired on %d changed pairs, %d contradictions", fast, contradictions)
	return fast
}

// reportLineDiff reports the first differing line between two
// normalized listings, tolerating different line counts: equal byte
// length does not imply equal instruction count.
func reportLineDiff(t *testing.T, msg string, oldLines, newLines []string) {
	t.Helper()
	for i := range min(len(oldLines), len(newLines)) {
		if oldLines[i] != newLines[i] {
			t.Errorf("%s at line %d:\n  old %q\n  new %q", msg, i, oldLines[i], newLines[i])
			return
		}
	}
	t.Errorf("%s: line counts differ (old %d, new %d)", msg, len(oldLines), len(newLines))
}
