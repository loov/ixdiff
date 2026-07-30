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
	"os"
	"os/signal"
	"strconv"

	"github.com/zeebo/clingy"
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

	// ponytail: placeholder until the pipeline is wired up.
	fmt.Fprintf(clingy.Stdout(ctx), "comparing %s -> %s (fn=%q top=%d sort=%s)\n",
		c.oldPath, c.newPath, c.fn, c.top, c.sortBy)
	return nil
}
