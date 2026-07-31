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
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	"github.com/zeebo/clingy"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/fndiff"
	"github.com/loov/ixdiff/internal/objfile"
)

func main() {
	// The flag is also declared in Setup so it appears in --help, but
	// clingy requires the two binary arguments, so a bare --version is
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
	stateSet map[fndiff.State]bool
	maskSP   bool
	json     bool
	sideBy   bool
	blocks   bool
	all      bool
	version  bool
	color    string
	pal      palette

	oldPath string
	newPath string
}

// setState marks s as kept by the --state filter, initializing the set
// on first use.
func (c *cmdDiff) setState(s fndiff.State) {
	if c.stateSet == nil {
		c.stateSet = map[fndiff.State]bool{}
	}
	c.stateSet[s] = true
}

// norm returns the normalization options selected by flags.
func (c *cmdDiff) norm() disasm.Options {
	return disasm.Options{MaskSP: c.maskSP}
}

// Setup declares the flags and arguments for the diff command.
func (c *cmdDiff) Setup(params clingy.Parameters) {
	c.fns = params.Flag("fn", "diff the function with this name or substring (repeatable)", []string(nil),
		clingy.Repeated).([]string)
	c.filters = params.Flag("filter", "limit the summary to functions containing this substring, ~regexp (repeatable)", []string(nil),
		clingy.Repeated).([]string)
	c.top = params.Flag("top", "number of functions to list in ranking tables", 100,
		clingy.Transform(strconv.Atoi)).(int)
	c.sortBy = params.Flag("sort", "ranking order for tables: size, insts, or name", "size").(string)
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

	c.oldPath = params.Arg("old", "path to the baseline binary").(string)
	c.newPath = params.Arg("new", "path to the changed binary").(string)
}

// Execute runs the comparison and writes the report to stdout.
func (c *cmdDiff) Execute(ctx context.Context) error {
	if c.version {
		fmt.Fprintln(clingy.Stdout(ctx), version())
		return nil
	}
	switch c.sortBy {
	case "size", "insts", "name":
	default:
		return fmt.Errorf("unknown sort order %q, expected size, insts, or name", c.sortBy)
	}
	for _, s := range c.states {
		switch s {
		case "changed":
			c.setState(fndiff.StateChanged)
		case "added":
			c.setState(fndiff.StateAdded)
		case "removed":
			c.setState(fndiff.StateRemoved)
		default:
			return fmt.Errorf("unknown --state %q, expected changed, added, or removed", s)
		}
	}
	var err error
	if c.pal, err = resolvePalette(c.color); err != nil {
		return err
	}

	old, err := objfile.Open(c.oldPath)
	if err != nil {
		return fmt.Errorf("opening old binary: %w", err)
	}
	defer old.Close()
	new, err := objfile.Open(c.newPath)
	if err != nil {
		return fmt.Errorf("opening new binary: %w", err)
	}
	defer new.Close()
	if old.Arch != new.Arch {
		return fmt.Errorf("architecture mismatch: %v vs %v", old.Arch, new.Arch)
	}

	pairs := fndiff.Compare(old, new)
	pairs = fndiff.MatchRenames(pairs, bodySimilar(old, new, c.norm()))
	stdout := clingy.Stdout(ctx)

	if len(c.fns) > 0 {
		return c.executeFuncs(stdout, pairs, old, new)
	}

	pairs, err = filterPairs(pairs, c.filters)
	if err != nil {
		return err
	}

	var nonIdentical []*fndiff.Pair
	for _, p := range pairs {
		if p.State != fndiff.StateIdentical {
			nonIdentical = append(nonIdentical, p)
		}
	}
	analyzed, err := analyze(nonIdentical, old, new, runtime.NumCPU(), c.norm())
	if err != nil {
		return err
	}
	if c.json {
		return c.writeJSONSummary(stdout, old.Arch.String(), pairs, analyzed, old, new)
	}
	writeSummary(stdout, pairs, analyzed, c.top, c.sortBy, c.stateSet)
	if c.all {
		return c.writeAll(stdout, pairs, analyzed, old, new)
	}
	return nil
}

// writeAll appends a diff section for every function in the ranking
// table, in table order, so one invocation yields a complete report.
func (c *cmdDiff) writeAll(w io.Writer, pairs []*fndiff.Pair, analyzed []*analysis, old, new *objfile.Binary) error {
	byName := make(map[string]*analysis, len(analyzed))
	for _, a := range analyzed {
		byName[a.pair.Name] = a
	}
	for _, p := range rankPairs(pairs, instDeltas(analyzed), c.top, c.sortBy, c.stateSet) {
		fmt.Fprintln(w)
		a := byName[p.Name]
		switch p.State {
		case fndiff.StateChanged:
			if c.blocks {
				if err := writeFuncBlocks(w, p, old, new, c.norm(), c.pal, c.sideBy); err != nil {
					return err
				}
				continue
			}
		case fndiff.StateAdded, fndiff.StateRemoved:
			fmt.Fprintf(w, "%s is %v (%+d bytes)\n", p.Name, p.State, p.SizeDelta())
			var err error
			if a, err = listing(p, old, new, c.norm()); err != nil {
				return err
			}
		}
		if c.sideBy {
			writeFuncDiffSide(w, a, c.pal)
		} else {
			writeFuncDiff(w, a, c.pal)
		}
	}
	return nil
}

// executeFuncs reports the assembly diff of every function named by a
// --fn flag, in the order given, separated by blank lines.
func (c *cmdDiff) executeFuncs(w io.Writer, pairs []*fndiff.Pair, old, new *objfile.Binary) error {
	if c.json {
		return c.writeJSONFuncs(w, pairs, old, new)
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
				fmt.Fprintf(w, "  %-9v %+7d bytes  %s\n", p.State, p.SizeDelta(), p.Name)
			}
			continue
		}
		if err := c.writeFunc(w, matches[0], old, new); err != nil {
			return err
		}
	}
	return nil
}

// writeJSONFuncs emits the --fn reports as one JSON array. A uniquely
// matched changed function includes its full diff; ambiguous matches
// are listed without one, mirroring the text output.
func (c *cmdDiff) writeJSONFuncs(w io.Writer, pairs []*fndiff.Pair, old, new *objfile.Binary) error {
	var reports []jsonFuncReport
	for _, name := range c.fns {
		matches, err := matchFuncs(pairs, name)
		if err != nil {
			return err
		}
		withDiff := len(matches) == 1
		for _, p := range matches {
			var a *analysis
			switch p.State {
			case fndiff.StateChanged:
				analyzed, err := analyze([]*fndiff.Pair{p}, old, new, 1, c.norm())
				if err != nil {
					return err
				}
				a = analyzed[0]
			case fndiff.StateAdded, fndiff.StateRemoved:
				if withDiff {
					var err error
					if a, err = listing(p, old, new, c.norm()); err != nil {
						return err
					}
				}
			}
			reports = append(reports, funcReport(p, a, withDiff))
		}
	}
	return encodeJSON(w, reports)
}

// filterPairs keeps pairs whose name matches any filter: a substring,
// or a regular expression when prefixed with ~. Without filters all
// pairs are kept.
func filterPairs(pairs []*fndiff.Pair, filters []string) ([]*fndiff.Pair, error) {
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
	var kept []*fndiff.Pair
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
func (c *cmdDiff) writeFunc(w io.Writer, p *fndiff.Pair, old, new *objfile.Binary) error {
	var a *analysis
	switch p.State {
	case fndiff.StateIdentical:
		fmt.Fprintf(w, "%s is byte-identical in both binaries\n", p.Name)
		return nil
	case fndiff.StateAdded, fndiff.StateRemoved:
		fmt.Fprintf(w, "%s is %v (%+d bytes)\n", p.Name, p.State, p.SizeDelta())
		var err error
		if a, err = listing(p, old, new, c.norm()); err != nil {
			return err
		}
	default:
		if c.blocks {
			return writeFuncBlocks(w, p, old, new, c.norm(), c.pal, c.sideBy)
		}
		analyzed, err := analyze([]*fndiff.Pair{p}, old, new, 1, c.norm())
		if err != nil {
			return err
		}
		a = analyzed[0]
	}
	if c.sideBy {
		writeFuncDiffSide(w, a, c.pal)
	} else {
		writeFuncDiff(w, a, c.pal)
	}
	return nil
}
