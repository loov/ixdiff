// Command ixdiff compares the assembly of two binaries.
//
// It is intended for understanding how compiler or build-flag changes
// affect the generated code: which functions changed, by how much, and
// what the instruction-level differences are.
//
// Usage:
//
//	ixdiff <old> <new>                     summary and top-N tables
//	ixdiff <binary>                        stats of a single binary
//	ixdiff --fn main.main <binary>         disassembly of one function
//	ixdiff --fn runtime.mapaccess1 a b     assembly diff of one function
//	ixdiff --top 100 --sort insts a b      rank by instruction-count delta
package main

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"

	"github.com/zeebo/clingy"

	"github.com/loov/disasm/objfile"
	"github.com/loov/ixdiff/ixdiff"
)

func main() {
	// The flag is also declared in Setup so it appears in --help, but
	// clingy requires the binary argument, so a bare --version is
	// answered before it runs.
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version())
		return
	}

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

// version reports the module version and VCS revision recorded in the
// build info.
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	v := info.Main.Version
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			v += " (" + s.Value[:12] + ")"
		}
	}
	return v
}

// cmdDiff compares two binaries and reports their assembly differences.
type cmdDiff struct {
	fns     []string
	filters []string
	top     int
	sortBy  string
	states  []string
	// stateSet is states parsed for rankPairs; nil keeps every state.
	stateSet map[ixdiff.State]bool
	maskSP   bool
	json     bool
	sideBy   bool
	blocks   bool
	all      bool
	version  bool
	color    string
	cpuProf  string
	memProf  string
	pal      palette

	oldPath string
	newPath string

	// objOld and objNew are the raw object files, opened by Execute
	// only for the --blocks renderer, which decodes functions itself.
	objOld, objNew *objfile.Binary
}

// setState marks the states kept by a --state value, initializing the
// set on first use. "changed" also keeps relocation-only pairs, which
// the tables display as changed.
func (c *cmdDiff) setState(states ...ixdiff.State) {
	if c.stateSet == nil {
		c.stateSet = map[ixdiff.State]bool{}
	}
	for _, s := range states {
		c.stateSet[s] = true
	}
}

// Setup declares the flags and arguments for the diff command.
func (c *cmdDiff) Setup(params clingy.Parameters) {
	c.fns = params.Flag("fn", "diff the function with this name or substring (repeatable)", []string(nil),
		clingy.Repeated).([]string)
	c.filters = params.Flag("filter", "limit the summary to functions containing this substring, ~regexp (repeatable)", []string(nil),
		clingy.Repeated).([]string)
	c.top = params.Flag("top", "number of functions to list in ranking tables", 100,
		clingy.Transform(strconv.Atoi)).(int)
	c.sortBy = params.Flag("sort", "ranking order for tables: size, insts, spills, slots, or name", "size").(string)
	c.states = params.Flag("state", "limit tables to functions in this state: changed, added, or removed (repeatable)", []string(nil),
		clingy.Repeated).([]string)
	c.maskSP = params.Flag("mask-sp", "ignore stack-offset shifts caused by frame size changes", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean).(bool)
	c.json = params.Flag("json", "emit machine-readable JSON instead of text", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean).(bool)
	c.sideBy = params.Flag("side-by-side", "show function diffs as two columns", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean).(bool)
	c.blocks = params.Flag("blocks", "match basic blocks before diffing, tolerating block reordering", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean).(bool)
	c.all = params.Flag("all", "follow the summary with a diff of every function in the ranking table", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean).(bool)
	c.color = params.Flag("color", "colorize diffs: auto, always, or never", "auto").(string)
	c.version = params.Flag("version", "print the module version and VCS revision", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean).(bool)
	c.cpuProf = params.Flag("cpuprofile", "write a CPU profile to this file", "", clingy.Advanced).(string)
	c.memProf = params.Flag("memprofile", "write a heap profile to this file at exit", "", clingy.Advanced).(string)

	c.oldPath = params.Arg("old", "path to the baseline binary").(string)
	if p := params.Arg("new", "path to the changed binary; omitted: report on old alone", clingy.Optional).(*string); p != nil {
		c.newPath = *p
	}
}

// Execute runs the comparison and writes the report to stdout.
func (c *cmdDiff) Execute(ctx context.Context) error {
	if c.version {
		fmt.Fprintln(clingy.Stdout(ctx), version())
		return nil
	}
	switch c.sortBy {
	case "size", "insts", "spills", "slots", "name":
	default:
		return fmt.Errorf("unknown sort order %q, expected size, insts, spills, slots, or name", c.sortBy)
	}
	for _, s := range c.states {
		switch s {
		case "changed":
			c.setState(ixdiff.Changed, ixdiff.RelocationOnly)
		case "added":
			c.setState(ixdiff.Added)
		case "removed":
			c.setState(ixdiff.Removed)
		default:
			return fmt.Errorf("unknown --state %q, expected changed, added, or removed", s)
		}
	}
	var err error
	if c.pal, err = resolvePalette(c.color); err != nil {
		return err
	}
	if c.cpuProf != "" {
		f, err := os.Create(c.cpuProf)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}
	if c.memProf != "" {
		defer func() {
			if err := writeHeapProfile(c.memProf); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
	}

	old, err := ixdiff.Open(c.oldPath)
	if err != nil {
		return fmt.Errorf("opening old binary: %w", err)
	}
	defer old.Close()
	stdout := clingy.Stdout(ctx)
	if c.newPath == "" {
		if len(c.fns) > 0 {
			return writeFuncListings(stdout, old, c.fns)
		}
		return writeStats(stdout, old, c.top)
	}
	new, err := ixdiff.Open(c.newPath)
	if err != nil {
		return fmt.Errorf("opening new binary: %w", err)
	}
	defer new.Close()

	d, err := ixdiff.Compare(old, new, &ixdiff.Options{MaskSP: c.maskSP})
	if err != nil {
		return err
	}

	if c.blocks && (c.all || len(c.fns) > 0) {
		// The blocks renderer decodes and normalizes functions itself,
		// which needs the raw object files.
		if c.objOld, err = objfile.Open(c.oldPath); err != nil {
			return fmt.Errorf("opening old binary: %w", err)
		}
		defer c.objOld.Close()
		if c.objNew, err = objfile.Open(c.newPath); err != nil {
			return fmt.Errorf("opening new binary: %w", err)
		}
		defer c.objNew.Close()
	}

	pairs := d.Pairs()

	if len(c.fns) > 0 {
		return c.executeFuncs(stdout, d, pairs)
	}

	pairs, err = filterPairs(pairs, c.filters)
	if err != nil {
		return err
	}

	if c.json {
		return c.writeJSONSummary(stdout, old.Arch(), d, pairs)
	}
	writeSummary(stdout, pairs, c.top, c.sortBy, c.stateSet)
	if c.all {
		return c.writeAll(stdout, d, pairs)
	}
	return nil
}

// writeHeapProfile writes the heap profile to path after a collection,
// so in-use figures reflect what the run retained; the allocation
// totals are unaffected.
func writeHeapProfile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	runtime.GC()
	return pprof.Lookup("allocs").WriteTo(f, 0)
}

// writeAll appends a diff section for every function in the ranking
// table, in table order, so one invocation yields a complete report.
func (c *cmdDiff) writeAll(w io.Writer, d *ixdiff.Diff, pairs []ixdiff.Pair) error {
	for _, p := range rankPairs(pairs, c.top, c.sortBy, c.stateSet) {
		fmt.Fprintln(w)
		switch p.State {
		case ixdiff.Changed, ixdiff.RelocationOnly:
			if c.blocks {
				if err := c.writeFuncBlocks(w, p); err != nil {
					return err
				}
				continue
			}
		case ixdiff.Added, ixdiff.Removed:
			fmt.Fprintf(w, "%s is %v (%+d bytes)\n", p.Name, p.State, p.SizeDelta)
		}
		lines, err := d.Lines(p)
		if err != nil {
			return err
		}
		if c.sideBy {
			writeFuncDiffSide(w, p, lines, c.pal)
		} else {
			writeFuncDiff(w, p, lines, c.pal)
		}
	}
	return nil
}

// executeFuncs reports the assembly diff of every function named by a
// --fn flag, in the order given, separated by blank lines.
func (c *cmdDiff) executeFuncs(w io.Writer, d *ixdiff.Diff, pairs []ixdiff.Pair) error {
	if c.json {
		return c.writeJSONFuncs(w, d, pairs)
	}
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
				fmt.Fprintf(w, "  %-9s %+7d bytes  %s\n", displayState(p.State), p.SizeDelta, p.Name)
			}
			continue
		}
		if err := c.writeFunc(w, d, matches[0]); err != nil {
			return err
		}
	}
	return nil
}

// filterPairs keeps pairs whose name matches any filter: a substring,
// or a regular expression when prefixed with ~. Without filters all
// pairs are kept.
func filterPairs(pairs []ixdiff.Pair, filters []string) ([]ixdiff.Pair, error) {
	if len(filters) == 0 {
		return pairs, nil
	}
	matchers := make([]func(string) bool, 0, len(filters))
	for _, f := range filters {
		if pattern, ok := strings.CutPrefix(f, "~"); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid --filter %q: %w", f, err)
			}
			matchers = append(matchers, re.MatchString)
		} else {
			matchers = append(matchers, func(name string) bool {
				return strings.Contains(name, f)
			})
		}
	}
	var kept []ixdiff.Pair
	for _, p := range pairs {
		for _, match := range matchers {
			if match(p.Name) {
				kept = append(kept, p)
				break
			}
		}
	}
	return kept, nil
}

// matchFuncs resolves a --fn value: an exact name wins, otherwise all
// substring matches are returned. With no match at all the error
// suggests the closest known names.
func matchFuncs(pairs []ixdiff.Pair, name string) ([]ixdiff.Pair, error) {
	var matches []ixdiff.Pair
	for _, p := range pairs {
		if p.Name == name {
			return []ixdiff.Pair{p}, nil
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
func closestNames(pairs []ixdiff.Pair, name string, n int) []string {
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
func (c *cmdDiff) writeFunc(w io.Writer, d *ixdiff.Diff, p ixdiff.Pair) error {
	switch p.State {
	case ixdiff.Identical:
		fmt.Fprintf(w, "%s is byte-identical in both binaries\n", p.Name)
		return nil
	case ixdiff.Added, ixdiff.Removed:
		fmt.Fprintf(w, "%s is %v (%+d bytes)\n", p.Name, p.State, p.SizeDelta)
	default:
		if c.blocks {
			return c.writeFuncBlocks(w, p)
		}
	}
	lines, err := d.Lines(p)
	if err != nil {
		return err
	}
	if c.sideBy {
		writeFuncDiffSide(w, p, lines, c.pal)
	} else {
		writeFuncDiff(w, p, lines, c.pal)
	}
	return nil
}
