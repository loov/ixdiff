package main

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/zeebo/clingy"

	"github.com/loov/disasm/objfile"
	"github.com/loov/ixdiff/internal/norm"
	"github.com/loov/ixdiff/internal/testbin"
)

// run executes the CLI with args and returns its stdout.
func run(t *testing.T, args ...string) string {
	t.Helper()
	var out strings.Builder
	ok, err := clingy.Environment{
		Name:   "ixdiff",
		Root:   new(cmdDiff),
		Args:   args,
		Stdout: &out,
		Stderr: &out,
	}.Run(context.Background(), nil)
	if err != nil || !ok {
		t.Fatalf("run %v: ok=%v err=%v\n%s", args, ok, err, out.String())
	}
	return out.String()
}

// runErr executes the CLI with args and returns the resulting error.
func runErr(t *testing.T, args ...string) error {
	t.Helper()
	_, err := clingy.Environment{
		Name:   "ixdiff",
		Root:   new(cmdDiff),
		Args:   args,
		Stdout: new(strings.Builder),
		Stderr: new(strings.Builder),
	}.Run(context.Background(), nil)
	return err
}

// TestPipeline_InliningComparison is the end-to-end check: comparing a
// default build against one with inlining disabled must attribute the
// difference to changed functions and added CALLs.
func TestPipeline_InliningComparison(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", GCFlags: "-l"})

	out := run(t, base, noinline)

	for _, want := range []string{"functions:", "changed", "total text size delta:", "package delta:", "top "} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
	// Disabling inlining outlines main.add and main.sum again.
	if !strings.Contains(out, "main.sum") {
		t.Errorf("expected main.sum among changed functions:\n%s", out)
	}

	// Added and removed functions are disassembled too, so every
	// ranked row has a numeric instruction delta.
	if table := out[strings.Index(out, "top "):]; strings.Contains(table, " - ") {
		t.Errorf("ranking table still has '-' instruction deltas:\n%s", table)
	}
}

func TestPipeline_SelfComparisonIsQuiet(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	out := run(t, base, base)
	if !strings.Contains(out, "0 changed") {
		t.Errorf("self comparison reported changes:\n%s", out)
	}
	if !strings.Contains(out, "total text size delta: +0 bytes") {
		t.Errorf("self comparison reported size delta:\n%s", out)
	}
}

func TestPipeline_SingleFunctionDiff(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", GCFlags: "-l"})

	out := run(t, "--fn", "main.main", base, noinline)
	if !strings.Contains(out, "--- main.main") || !strings.Contains(out, "+++ main.main") {
		t.Errorf("missing diff header:\n%s", out)
	}
	if !strings.Contains(out, "@@ -") {
		t.Errorf("missing hunk headers:\n%s", out)
	}
	// Outlined calls must appear as inserted CALL lines with an
	// address column.
	if !regexp.MustCompile(`(?m)^\+[0-9a-f]+: CALL\s+main\.sum\(SB\)$`).MatchString(out) {
		t.Errorf("expected inserted CALL main.sum with address:\n%s", out)
	}

	// Side-by-side output pairs the inserted call into a marked row.
	out = run(t, "--side-by-side", "--fn", "main.main", base, noinline)
	if !regexp.MustCompile(`(?m)[|>] [0-9a-f]+: CALL\s+main\.sum\(SB\)$`).MatchString(out) {
		t.Errorf("expected marked side-by-side row for CALL main.sum:\n%s", out)
	}

	// Repeated --fn reports each function in the order given.
	out = run(t, "--fn", "main.main", "--fn", "main.sum", base, noinline)
	main, sum := strings.Index(out, "--- main.main"), strings.Index(out, "main.sum is")
	if main < 0 || sum < 0 || sum < main {
		t.Errorf("expected main.main diff followed by main.sum report:\n%s", out)
	}

	// An added function prints a full all-insert listing.
	out = run(t, "--fn", "main.sum", base, noinline)
	if !strings.Contains(out, "--- main.sum (absent)") ||
		!regexp.MustCompile(`(?m)^\+[0-9a-f]+: RET`).MatchString(out) {
		t.Errorf("expected full listing for added main.sum:\n%s", out)
	}
}

// TestPipeline_MaskSPMasksStackOffsets checks that --mask-sp reaches
// the diff output on both an SP-named architecture and one whose stack
// pointer is a numbered register (R1 on ppc64le).
func TestPipeline_MaskSPMasksStackOffsets(t *testing.T) {
	for _, arch := range []string{"amd64", "ppc64le"} {
		t.Run(arch, func(t *testing.T) {
			base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: arch})
			noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: arch, GCFlags: "-l"})

			out := run(t, "--mask-sp", "--fn", "main.main", base, noinline)
			if !strings.Contains(out, "<sp>(") {
				t.Errorf("expected masked stack displacements in diff:\n%s", out)
			}
		})
	}
}

// TestPipeline_AllAppendsRankedDiffs checks that --all follows the
// summary with a diff section per ranked function: changed functions
// get hunks, added ones a full listing, and the sections appear in
// ranking-table order.
func TestPipeline_AllAppendsRankedDiffs(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", GCFlags: "-l"})

	out := run(t, "--all", base, noinline)
	table := strings.Index(out, "top ")
	if table < 0 {
		t.Fatalf("missing ranking table:\n%s", out)
	}
	if !strings.Contains(out[table:], "--- main.main") || !strings.Contains(out, "@@ -") {
		t.Errorf("expected main.main diff section after the summary:\n%s", out)
	}
	if !strings.Contains(out, "main.sum is added") {
		t.Errorf("expected added-function listing section:\n%s", out)
	}

	// Sections follow the table order.
	var tableOrder, sectionOrder []int
	for _, name := range []string{"main.main", "main.sum"} {
		tableOrder = append(tableOrder, strings.Index(out[table:], " "+name+"\n"))
		sectionOrder = append(sectionOrder, strings.Index(out, "+++ "+name+" ("))
	}
	if (tableOrder[0] < tableOrder[1]) != (sectionOrder[0] < sectionOrder[1]) {
		t.Errorf("section order does not match table order:\n%s", out)
	}

	// --all --json attaches the diff to every ranked function.
	var report struct {
		Functions []struct {
			Name  string `json:"name"`
			State string `json:"state"`
			Diff  []any  `json:"diff"`
		} `json:"functions"`
	}
	if err := json.Unmarshal([]byte(run(t, "--all", "--json", base, noinline)), &report); err != nil {
		t.Fatalf("unmarshal --all --json: %v", err)
	}
	for _, fn := range report.Functions {
		if len(fn.Diff) == 0 {
			t.Errorf("ranked %s function %s has no diff in --all --json", fn.State, fn.Name)
		}
	}
}

// TestPipeline_BlocksSideBySide checks that --blocks renders its
// unmatched-instruction diff as two columns when --side-by-side is
// also given, instead of silently falling back to unified output.
func TestPipeline_BlocksSideBySide(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", GCFlags: "-l"})

	out := run(t, "--blocks", "--side-by-side", "--fn", "main.main", base, noinline)
	if !regexp.MustCompile(`(?m)[|>] [0-9a-f]+: `).MatchString(out) {
		t.Errorf("expected side-by-side marker rows with --blocks:\n%s", out)
	}
	if regexp.MustCompile(`(?m)^\+[0-9a-f]+: `).MatchString(out) {
		t.Errorf("unexpected unified insert lines with --blocks --side-by-side:\n%s", out)
	}
}

// TestPipeline_BlocksSplitsOnRISCV checks that block splitting works
// on an architecture whose returns and jumps decode under raw
// mnemonics absent from the terminator set (riscv64 JAL/JALR): the
// rendered RET of real main.main code must end its block, and the
// end-to-end --blocks diff must shrink against the plain one by
// matching unchanged blocks away.
func TestPipeline_BlocksSplitsOnRISCV(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "riscv64"})
	noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "riscv64", GCFlags: "-l"})

	bin, err := objfile.Open(base)
	if err != nil {
		t.Fatalf("open %s: %v", base, err)
	}
	defer bin.Close()
	fn := bin.Func("main.main")
	insts, err := bin.Disassemble(fn)
	if err != nil {
		t.Fatalf("decode main.main: %v", err)
	}
	nl := norm.NormalizeLines(fn.Name, insts, norm.Options{})
	ends := blockEnds(nl, insts)
	for i, in := range insts {
		if in.Text == "RET" && !ends[i] {
			t.Errorf("RET at %x (raw op %s) does not end a block", in.Addr, in.Op)
		}
	}

	plain := run(t, "--fn", "main.main", base, noinline)
	blocks := run(t, "--blocks", "--fn", "main.main", base, noinline)
	if strings.Count(blocks, "\n") >= strings.Count(plain, "\n") {
		t.Errorf("--blocks output is not smaller than the plain diff; block splitting degraded:\nplain:\n%s\nblocks:\n%s", plain, blocks)
	}
}

// TestPipeline_StateFilterAndNameSort checks the table-scoping flags:
// --state keeps only the requested states and --sort name orders the
// table alphabetically for stable CI output.
func TestPipeline_StateFilterAndNameSort(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", GCFlags: "-l"})

	out := run(t, "--state", "added", base, noinline)
	table := out[strings.Index(out, "top "):]
	if strings.Contains(table, " changed ") || strings.Contains(table, " removed ") {
		t.Errorf("--state added table contains other states:\n%s", table)
	}
	if !strings.Contains(table, " added ") {
		t.Errorf("--state added table has no added functions:\n%s", table)
	}

	out = run(t, "--sort", "name", base, noinline)
	table = out[strings.Index(out, "top "):]
	if !strings.Contains(table, "by name:") {
		t.Errorf("expected name-ordered table header:\n%s", table)
	}
	var names []string
	for _, line := range strings.Split(table, "\n")[2:] {
		if fields := strings.Fields(line); len(fields) >= 6 {
			names = append(names, fields[5])
		}
	}
	if len(names) < 2 || !slices.IsSorted(names) {
		t.Errorf("table rows not sorted by name: %v", names)
	}

	got, err := parse(t, "--state", "bogus", "a", "b")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := got.Execute(context.Background()); err == nil {
		t.Error("expected error for --state bogus, got nil")
	}
}

func TestPipeline_MissingFunctionErrors(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	var out strings.Builder
	_, err := clingy.Environment{
		Name:   "ixdiff",
		Root:   new(cmdDiff),
		Args:   []string{"--fn", "main.doesNotExist", base, base},
		Stdout: &out,
		Stderr: &out,
	}.Run(context.Background(), nil)
	if err == nil {
		t.Error("expected error for unknown function")
	}
}

func TestPipeline_ArchitectureMismatchErrors(t *testing.T) {
	amd64 := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	arm64 := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "arm64"})
	err := runErr(t, amd64, arm64)
	if err == nil || !strings.Contains(err.Error(), "architecture mismatch") {
		t.Errorf("comparing amd64 to arm64: err = %v, want architecture mismatch", err)
	}
}

func TestPipeline_UnknownColorModeErrors(t *testing.T) {
	// The palette resolves before the binaries open, so dummy paths do.
	if err := runErr(t, "--color", "bogus", "a", "b"); err == nil {
		t.Error("expected error for --color bogus, got nil")
	}
}

func TestPipeline_InvalidFilterRegexpErrors(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	err := runErr(t, "--filter", "~[", base, base)
	if err == nil || !strings.Contains(err.Error(), "invalid --filter") {
		t.Errorf("--filter ~[: err = %v, want invalid --filter", err)
	}
}

// TestPipeline_VersionFlagPrintsVersion covers the clingy --version
// flag. The bare `ixdiff --version` shortcut lives in main() and is
// not reachable from tests; this exercises the flag path it mirrors.
func TestPipeline_VersionFlagPrintsVersion(t *testing.T) {
	// Execute returns before opening the binaries, so dummy paths do.
	out := run(t, "--version", "a", "b")
	if strings.TrimSpace(out) == "" {
		t.Error("--version printed nothing")
	}
}

// TestPipeline_MultiArchSmoke runs the summary and a single-function
// diff on every supported architecture, checking the whole pipeline
// (open, decode, normalize, diff) holds together beyond amd64.
func TestPipeline_MultiArchSmoke(t *testing.T) {
	targets := []struct{ goos, goarch string }{
		{"linux", "amd64"}, {"linux", "arm64"}, {"linux", "arm"},
		{"linux", "386"}, {"linux", "riscv64"}, {"linux", "loong64"},
		{"linux", "s390x"}, {"linux", "ppc64"}, {"linux", "ppc64le"},
		{"wasip1", "wasm"},
	}
	for _, tt := range targets {
		t.Run(tt.goarch, func(t *testing.T) {
			base := testbin.Build(t, testbin.Config{GOOS: tt.goos, GOARCH: tt.goarch})
			noinline := testbin.Build(t, testbin.Config{GOOS: tt.goos, GOARCH: tt.goarch, GCFlags: "-l"})

			summary := run(t, base, noinline)
			if !strings.Contains(summary, "changed") || !strings.Contains(summary, "total text size delta:") {
				t.Errorf("implausible summary:\n%s", summary)
			}
			fn := run(t, "--fn", "main.main", base, noinline)
			if !strings.Contains(fn, "@@ -") {
				t.Errorf("main.main diff has no hunks:\n%s", fn)
			}
		})
	}
}

func TestPipeline_ColorModes(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", GCFlags: "-l"})

	plain := run(t, "--fn", "main.main", base, noinline)
	if strings.Contains(plain, "\x1b[") {
		t.Error("default (non-tty) output contains escape codes")
	}
	colored := run(t, "--color", "always", "--fn", "main.main", base, noinline)
	if !strings.Contains(colored, "\x1b[32m") || !strings.Contains(colored, "\x1b[31m") {
		t.Error("--color always output lacks insert/delete colors")
	}
	if out := run(t, "--color", "never", "--fn", "main.main", base, noinline); strings.Contains(out, "\x1b[") {
		t.Error("--color never output contains escape codes")
	}
}

func TestPipeline_FilterScopesSummary(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", GCFlags: "-l"})

	out := run(t, "--filter", "main.", base, noinline)
	if strings.Contains(out, "runtime.") || strings.Contains(out, "slices.") {
		t.Errorf("--filter main. leaked other packages:\n%s", out)
	}
	if !strings.Contains(out, "main.sum") {
		t.Errorf("--filter main. lost main functions:\n%s", out)
	}

	if out := run(t, "--filter", "~^main\\.(sum|add)$", base, noinline); !strings.Contains(out, "main.sum") {
		t.Errorf("regexp filter did not match main.sum:\n%s", out)
	}
}

func TestPipeline_JSONOutput(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", GCFlags: "-l"})

	var summary struct {
		Arch   string `json:"arch"`
		Counts struct {
			Identical int `json:"identical"`
			Changed   int `json:"changed"`
		} `json:"counts"`
		SizeDelta int64          `json:"size_delta"`
		OpDelta   map[string]int `json:"op_delta"`
		Functions []struct {
			Name      string `json:"name"`
			State     string `json:"state"`
			SizeDelta int64  `json:"size_delta"`
			InstDelta *int   `json:"inst_delta"`
		} `json:"functions"`
	}
	if err := json.Unmarshal([]byte(run(t, "--json", base, noinline)), &summary); err != nil {
		t.Fatalf("summary is not valid JSON: %v", err)
	}
	if summary.Arch != "amd64" || summary.Counts.Identical == 0 || summary.Counts.Changed == 0 {
		t.Errorf("implausible summary: %+v", summary)
	}
	if len(summary.Functions) == 0 || summary.Functions[0].InstDelta == nil {
		t.Errorf("ranked functions missing inst_delta: %+v", summary.Functions)
	}

	var funcs []struct {
		Name  string `json:"name"`
		State string `json:"state"`
		Diff  []struct {
			Op   string `json:"op"`
			Text string `json:"text"`
		} `json:"diff"`
	}
	if err := json.Unmarshal([]byte(run(t, "--json", "--fn", "main.main", base, noinline)), &funcs); err != nil {
		t.Fatalf("--fn output is not valid JSON: %v", err)
	}
	if len(funcs) != 1 || funcs[0].State != "changed" || len(funcs[0].Diff) == 0 {
		t.Errorf("expected one changed function with a diff: %+v", funcs)
	}
}

func TestPipeline_TopAndSortFlags(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", GCFlags: "-l"})

	out := run(t, "--top", "3", "--sort", "insts", base, noinline)
	if !strings.Contains(out, "by insts delta:") {
		t.Errorf("missing insts ranking table:\n%s", out)
	}
	if rows := strings.Count(out[strings.Index(out, "by insts delta:"):], "\n") - 2; rows > 3 {
		t.Errorf("ranking table has %d rows, want at most 3:\n%s", rows, out)
	}
}
