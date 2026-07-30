package main

import (
	"context"
	"strings"
	"testing"

	"github.com/zeebo/clingy"

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

// TestPipeline_InliningComparison is the end-to-end check: comparing a
// default build against one with inlining disabled must attribute the
// difference to changed functions and added CALLs.
func TestPipeline_InliningComparison(t *testing.T) {
	base := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})
	noinline := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", GCFlags: "-l"})

	out := run(t, base, noinline)

	for _, want := range []string{"functions:", "changed", "total text size delta:", "top "} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
	// Disabling inlining outlines main.add and main.sum again.
	if !strings.Contains(out, "main.sum") {
		t.Errorf("expected main.sum among changed functions:\n%s", out)
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
	// Outlined calls must appear as inserted CALL lines.
	if !strings.Contains(out, "+CALL main.sum(SB)") {
		t.Errorf("expected inserted CALL main.sum:\n%s", out)
	}

	// Repeated --fn reports each function in the order given.
	out = run(t, "--fn", "main.main", "--fn", "main.sum", base, noinline)
	main, sum := strings.Index(out, "--- main.main"), strings.Index(out, "main.sum is")
	if main < 0 || sum < 0 || sum < main {
		t.Errorf("expected main.main diff followed by main.sum report:\n%s", out)
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
