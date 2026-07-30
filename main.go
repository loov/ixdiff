// Command ixdiff compares the assembly of two binaries.
//
// It is intended for understanding how compiler or build-flag changes
// affect the generated code: which functions changed, by how much, and
// what the instruction-level differences are.
//
// Usage:
//
//	ixdiff <old> <new>                     summary and top-N tables
//	ixdiff --fn runtime.mapaccess1 a b     assembly diff of one function
//	ixdiff --top 100 --sort insts a b      rank by instruction-count delta
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"

	"github.com/zeebo/clingy"

	"github.com/loov/ixdiff/internal/fndiff"
	"github.com/loov/ixdiff/internal/objfile"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	ok, err := clingy.Environment{
		Name: "ixdiff",
		Root: new(cmdDiff),
	}.Run(ctx, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	if !ok || err != nil {
		os.Exit(1)
	}
}

// cmdDiff compares two binaries and reports their assembly differences.
type cmdDiff struct {
	fn     string
	top    int
	sortBy string

	oldPath string
	newPath string
}

// Setup declares the flags and arguments for the diff command.
func (c *cmdDiff) Setup(params clingy.Parameters) {
	c.fn = params.Flag("fn", "show the assembly diff of a single function", "").(string)
	c.top = params.Flag("top", "number of functions to list in ranking tables", 100,
		clingy.Transform(strconv.Atoi)).(int)
	c.sortBy = params.Flag("sort", "ranking order for tables: size or insts", "size").(string)

	c.oldPath = params.Arg("old", "path to the baseline binary").(string)
	c.newPath = params.Arg("new", "path to the changed binary").(string)
}

// Execute runs the comparison and writes the report to stdout.
func (c *cmdDiff) Execute(ctx context.Context) error {
	switch c.sortBy {
	case "size", "insts":
	default:
		return fmt.Errorf("unknown sort order %q, expected size or insts", c.sortBy)
	}

	old, err := objfile.Open(c.oldPath)
	if err != nil {
		return fmt.Errorf("opening old binary: %w", err)
	}
	new, err := objfile.Open(c.newPath)
	if err != nil {
		return fmt.Errorf("opening new binary: %w", err)
	}
	if old.Arch != new.Arch {
		return fmt.Errorf("architecture mismatch: %v vs %v", old.Arch, new.Arch)
	}

	pairs := fndiff.Compare(old, new)
	stdout := clingy.Stdout(ctx)

	if c.fn != "" {
		return c.executeFunc(stdout, pairs, old, new)
	}

	var changedPairs []*fndiff.Pair
	for _, p := range pairs {
		if p.State == fndiff.StateChanged {
			changedPairs = append(changedPairs, p)
		}
	}
	changed, err := analyzeChanged(changedPairs, old, new, runtime.NumCPU())
	if err != nil {
		return err
	}
	writeSummary(stdout, pairs, changed, c.top, c.sortBy)
	return nil
}

// executeFunc reports the assembly diff of the single function named
// by --fn.
func (c *cmdDiff) executeFunc(w io.Writer, pairs []*fndiff.Pair, old, new *objfile.Binary) error {
	i := slices.IndexFunc(pairs, func(p *fndiff.Pair) bool { return p.Name == c.fn })
	if i < 0 {
		return fmt.Errorf("function %q not found in either binary", c.fn)
	}
	p := pairs[i]
	switch p.State {
	case fndiff.StateIdentical:
		fmt.Fprintf(w, "%s is byte-identical in both binaries\n", p.Name)
		return nil
	case fndiff.StateAdded, fndiff.StateRemoved:
		fmt.Fprintf(w, "%s is %v (%+d bytes)\n", p.Name, p.State, p.SizeDelta())
		return nil
	}
	changed, err := analyzeChanged([]*fndiff.Pair{p}, old, new, 1)
	if err != nil {
		return err
	}
	writeFuncDiff(w, changed[0])
	return nil
}
