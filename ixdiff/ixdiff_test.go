package ixdiff_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/loov/ixdiff/internal/testbin"
	"github.com/loov/ixdiff/ixdiff"
)

// open opens the fixture binary built with cfg and closes it with the
// test.
func open(t *testing.T, cfg testbin.Config) *ixdiff.Binary {
	t.Helper()
	bin, err := ixdiff.Open(testbin.Build(t, cfg))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = bin.Close() })
	return bin
}

// compare compares the fixture binaries built with the two configs.
func compare(t *testing.T, oldCfg, newCfg testbin.Config) *ixdiff.Diff {
	t.Helper()
	d, err := ixdiff.Compare(open(t, oldCfg), open(t, newCfg), nil)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	return d
}

var (
	base     = testbin.Config{GOOS: "linux", GOARCH: "amd64"}
	noinline = testbin.Config{GOOS: "linux", GOARCH: "amd64", GCFlags: "-l"}
	padded   = testbin.Config{GOOS: "linux", GOARCH: "amd64", Tags: "pad"}
)

func TestBinary_OpenReportsLayout(t *testing.T) {
	bin := open(t, base)

	if got := bin.Arch(); got != "amd64" {
		t.Errorf("Arch = %q, want amd64", got)
	}
	if bin.Path() == "" {
		t.Error("Path is empty")
	}

	funcs := bin.Funcs()
	if len(funcs) == 0 {
		t.Fatal("no functions")
	}
	for i := 1; i < len(funcs); i++ {
		if funcs[i].Addr < funcs[i-1].Addr {
			t.Fatalf("Funcs not in address order at %d: %x after %x",
				i, funcs[i].Addr, funcs[i-1].Addr)
		}
	}

	main, ok := bin.Func("main.main")
	if !ok {
		t.Fatal("Func(main.main) not found")
	}
	if main.Package != "main" || main.Size <= 0 || len(main.Code()) != int(main.Size) {
		t.Errorf("main.main = {Package: %q, Size: %d, len(Code): %d}, want package main with matching sizes",
			main.Package, main.Size, len(main.Code()))
	}

	insts, err := main.Text()
	if err != nil || len(insts) == 0 {
		t.Fatalf("Text = %d insts, %v; want some instructions", len(insts), err)
	}
	if insts[0].Addr != main.Addr || insts[0].Text == "" {
		t.Errorf("first inst = %+v, want text at %x", insts[0], main.Addr)
	}
	ops, err := main.Ops()
	if err != nil || ops.Total() == 0 {
		t.Fatalf("Ops = %v, %v; want a non-empty histogram", ops, err)
	}
	if _, ok := ops["BYTE"]; ok {
		t.Error("Ops includes BYTE pseudo-instructions")
	}

	if got := bin.TextBytes(); got <= 0 {
		t.Errorf("TextBytes = %d, want positive", got)
	}
	// Go inserts alignment padding between functions; the fixture is
	// far too small for large inter-function gaps.
	if pad := bin.Padding(); pad.Align <= 0 || pad.Large < 0 {
		t.Errorf("Padding = %+v, want positive Align", pad)
	}
}

func TestCompare_ClassifiesEveryPair(t *testing.T) {
	d := compare(t, base, noinline)

	pairs := d.Pairs()
	counts := map[ixdiff.State]int{}
	for _, p := range pairs {
		counts[p.State]++
	}
	total := 0
	for s, n := range counts {
		if s < ixdiff.Identical || s > ixdiff.Removed {
			t.Errorf("unexpected state %v", s)
		}
		total += n
	}
	if total != len(pairs) {
		t.Errorf("state counts sum to %d, want len(Pairs) = %d", total, len(pairs))
	}
	for _, s := range []ixdiff.State{ixdiff.Identical, ixdiff.Changed, ixdiff.Added} {
		if counts[s] == 0 {
			t.Errorf("no %v pairs; comparison is vacuous", s)
		}
	}
	// The reverse comparison sees the outlined functions as removed.
	reverse := compare(t, noinline, base)
	removed := 0
	for _, p := range reverse.Pairs() {
		if p.State == ixdiff.Removed {
			removed++
		}
	}
	if removed == 0 {
		t.Error("reverse comparison has no removed pairs")
	}
}

func TestCompare_PadShiftIsRelocationOnly(t *testing.T) {
	d := compare(t, base, padded)
	reloc := 0
	for _, p := range d.Pairs() {
		if p.State == ixdiff.RelocationOnly {
			reloc++
			if p.InstDelta != 0 || len(p.OpDelta) != 0 {
				t.Errorf("%s: relocation-only pair has deltas: %d %v", p.Name, p.InstDelta, p.OpDelta)
			}
			lines, err := d.Lines(p)
			if err != nil || lines != nil {
				t.Errorf("%s: Lines = %d lines, %v; want none", p.Name, len(lines), err)
			}
		}
	}
	if reloc == 0 {
		t.Error("layout shift produced no relocation-only pairs")
	}
}

func TestDiff_LinesPerState(t *testing.T) {
	d := compare(t, base, noinline)
	seen := map[ixdiff.State]bool{}
	for _, p := range d.Pairs() {
		if seen[p.State] {
			continue
		}
		seen[p.State] = true
		lines, err := d.Lines(p)
		if err != nil {
			t.Fatalf("Lines(%s): %v", p.Name, err)
		}
		switch p.State {
		case ixdiff.Identical:
			if lines != nil {
				t.Errorf("%s: identical pair has %d lines", p.Name, len(lines))
			}
		case ixdiff.Changed:
			if len(lines) == 0 {
				t.Errorf("%s: changed pair has no lines", p.Name)
			}
		case ixdiff.Added:
			for _, l := range lines {
				if l.Op != ixdiff.Insert {
					t.Fatalf("%s: added pair has non-insert line %+v", p.Name, l)
				}
			}
			if len(lines) == 0 {
				t.Errorf("%s: added pair has no listing", p.Name)
			}
		case ixdiff.Removed:
			for _, l := range lines {
				if l.Op != ixdiff.Delete {
					t.Fatalf("%s: removed pair has non-delete line %+v", p.Name, l)
				}
			}
		}
	}
}

func TestDiff_AggregatesAreConsistent(t *testing.T) {
	d := compare(t, base, noinline)

	var sizeDelta int64
	for _, p := range d.Pairs() {
		sizeDelta += p.SizeDelta
	}
	if got := d.SizeDelta(); got != sizeDelta {
		t.Errorf("SizeDelta = %d, want pair sum %d", got, sizeDelta)
	}

	// Disabling inlining outlines functions, adding CALL instructions.
	if ops := d.OpDelta(); ops["CALL"] <= 0 {
		t.Errorf("OpDelta[CALL] = %d, want positive after -gcflags=-l", ops["CALL"])
	}

	pkgs := d.Packages()
	if len(pkgs) == 0 {
		t.Fatal("Packages is empty")
	}
	hasMain := false
	for _, pd := range pkgs {
		if pd.Name == "main" {
			hasMain = true
			if pd.Changed == 0 && pd.Added == 0 {
				t.Errorf("package main rollup has no changes: %+v", pd)
			}
		}
	}
	if !hasMain {
		t.Errorf("Packages misses main: %v", pkgs)
	}
}

func TestCompare_ArchitectureMismatchErrors(t *testing.T) {
	old := open(t, base)
	new := open(t, testbin.Config{GOOS: "linux", GOARCH: "arm64"})
	if _, err := ixdiff.Compare(old, new, nil); err == nil {
		t.Error("expected error comparing amd64 to arm64")
	}
}

// buildArchive compiles a single-file package into a Go compile
// archive; archives have pseudo-addresses instead of a memory layout.
func buildArchive(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go tool not available: %v", err)
	}
	dir := t.TempDir()
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o666); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module p\n\ngo 1.26\n")
	write("p.go", `package p

func Add(a, b int) int { return a + b }

func Greet(name string) string { return "hello " + name }
`)
	out := filepath.Join(dir, "p.a")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	return out
}

func TestBinary_GoArchiveHasNoPadding(t *testing.T) {
	bin, err := ixdiff.Open(buildArchive(t))
	if err != nil {
		t.Fatal(err)
	}
	defer bin.Close()

	if pad := bin.Padding(); pad != (ixdiff.Padding{}) {
		t.Errorf("Padding = %+v, want zero for an archive", pad)
	}
	funcs := bin.Funcs()
	if len(funcs) == 0 {
		t.Fatal("no functions in archive")
	}
	for i := 1; i < len(funcs); i++ {
		if funcs[i].Addr < funcs[i-1].Addr {
			t.Fatalf("archive Funcs not in address order at %d", i)
		}
	}
	if _, ok := bin.Func("p.Add"); !ok {
		t.Error("Func(p.Add) not found in archive")
	}
}
