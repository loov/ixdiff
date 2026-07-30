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
	"cmp"
	"runtime"
	"slices"
	"strconv"
	"strings"

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
	fns    []string
	top    int
	sortBy string

	oldPath string
	newPath string
}

// Setup declares the flags and arguments for the diff command.
func (c *cmdDiff) Setup(params clingy.Parameters) {
	c.fns = params.Flag("fn", "diff the function with this name or substring (repeatable)", []string(nil),
		clingy.Repeated).([]string)
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

	if len(c.fns) > 0 {
		return c.executeFuncs(stdout, pairs, old, new)
	}

	var nonIdentical []*fndiff.Pair
	for _, p := range pairs {
		if p.State != fndiff.StateIdentical {
			nonIdentical = append(nonIdentical, p)
		}
	}
	analyzed, err := analyze(nonIdentical, old, new, runtime.NumCPU())
	if err != nil {
		return err
	}
	writeSummary(stdout, pairs, analyzed, c.top, c.sortBy)
	return nil
}

// executeFuncs reports the assembly diff of every function named by a
// --fn flag, in the order given, separated by blank lines.
func (c *cmdDiff) executeFuncs(w io.Writer, pairs []*fndiff.Pair, old, new *objfile.Binary) error {
	for i, name := range c.fns {
		if i > 0 {
			fmt.Fprintln(w)
		}
		matches, err := matchFuncs(pairs, name)
		if err != nil {
			return err
		}
		if len(matches) > 1 {
			fmt.Fprintf(w, "%q matches %d functions:\n", name, len(matches))
			for _, p := range matches {
				fmt.Fprintf(w, "  %-9v %+7d bytes  %s\n", p.State, p.SizeDelta(), p.Name)
			}
			continue
		}
		if err := writeFunc(w, matches[0], old, new); err != nil {
			return err
		}
	}
	return nil
}

// matchFuncs resolves a --fn value: an exact name wins, otherwise all
// substring matches are returned. With no match at all the error
// suggests the closest known names.
func matchFuncs(pairs []*fndiff.Pair, name string) ([]*fndiff.Pair, error) {
	var matches []*fndiff.Pair
	for _, p := range pairs {
		if p.Name == name {
			return []*fndiff.Pair{p}, nil
		}
		if strings.Contains(p.Name, name) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		if close := closestNames(pairs, name, 3); len(close) > 0 {
			return nil, fmt.Errorf("function %q not found in either binary, did you mean: %s",
				name, strings.Join(close, ", "))
		}
		return nil, fmt.Errorf("function %q not found in either binary", name)
	}
	return matches, nil
}

// closestNames returns up to n function names nearest to name by
// Levenshtein distance, ignoring names that differ in more than half
// their length.
func closestNames(pairs []*fndiff.Pair, name string, n int) []string {
	type scored struct {
		name string
		dist int
	}
	var candidates []scored
	for _, p := range pairs {
		if d := levenshtein(name, p.Name); d <= max(len(name), len(p.Name))/2 {
			candidates = append(candidates, scored{p.Name, d})
		}
	}
	slices.SortFunc(candidates, func(a, b scored) int {
		if a.dist != b.dist {
			return a.dist - b.dist
		}
		return cmp.Compare(a.name, b.name)
	})
	names := make([]string, 0, n)
	for _, c := range candidates[:min(n, len(candidates))] {
		names = append(names, c.name)
	}
	return names
}

// levenshtein returns the edit distance between a and b using a
// two-row dynamic program.
func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// writeFunc reports one function pair: a note for identical, added,
// and removed functions, a full assembly diff for changed ones.
func writeFunc(w io.Writer, p *fndiff.Pair, old, new *objfile.Binary) error {
	switch p.State {
	case fndiff.StateIdentical:
		fmt.Fprintf(w, "%s is byte-identical in both binaries\n", p.Name)
		return nil
	case fndiff.StateAdded, fndiff.StateRemoved:
		fmt.Fprintf(w, "%s is %v (%+d bytes)\n", p.Name, p.State, p.SizeDelta())
		return nil
	}
	analyzed, err := analyze([]*fndiff.Pair{p}, old, new, 1)
	if err != nil {
		return err
	}
	writeFuncDiff(w, analyzed[0])
	return nil
}
