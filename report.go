package main

import (
	"cmp"
	"fmt"
	"io"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/fndiff"
	"github.com/loov/ixdiff/internal/objfile"
)

// analysis is the result of disassembling one non-identical pair.
type analysis struct {
	pair  *fndiff.Pair
	edits []fndiff.Edit
	// oldAddrs and newAddrs are the instruction addresses backing the
	// two sides of edits.
	oldAddrs, newAddrs []uint64
	// instDelta is new minus old instruction count.
	instDelta int
	// opDelta is the per-mnemonic count change.
	opDelta fndiff.OpCount
	// noise reports that the normalized instructions are equal:
	// the byte difference was pure relocation noise.
	noise bool
}

// analyze disassembles every non-identical pair, limited to limit-way
// concurrency. Changed pairs are additionally diffed; added and
// removed functions contribute only their instruction counts. The
// result keeps the input order.
func analyze(pairs []*fndiff.Pair, old, new *objfile.Binary, limit int) ([]*analysis, error) {
	oldLookup, newLookup := disasm.Lookup(old), disasm.Lookup(new)

	results := make([]*analysis, len(pairs))
	var g errgroup.Group
	g.SetLimit(limit)
	for i, p := range pairs {
		g.Go(func() error {
			var oldInsts, newInsts []disasm.Inst
			var err error
			if p.Old != nil {
				oldInsts, err = disasm.Decode(old.Arch, p.Old.Code(), p.Old.Addr, oldLookup)
				if err != nil {
					return fmt.Errorf("disassembling old %s: %w", p.Name, err)
				}
			}
			if p.New != nil {
				newInsts, err = disasm.Decode(new.Arch, p.New.Code(), p.New.Addr, newLookup)
				if err != nil {
					return fmt.Errorf("disassembling new %s: %w", p.Name, err)
				}
			}

			oldLines := disasm.Normalize(p.Name, oldInsts)
			newLines := disasm.Normalize(p.Name, newInsts)
			a := &analysis{
				pair:      p,
				instDelta: len(newInsts) - len(oldInsts),
				opDelta:   fndiff.CountOps(ops(oldInsts)).Delta(fndiff.CountOps(ops(newInsts))),
			}
			if p.State == fndiff.StateChanged {
				a.edits = fndiff.Diff(oldLines, newLines)
				a.noise = slices.Equal(oldLines, newLines)
				a.oldAddrs = addrs(oldInsts)
				a.newAddrs = addrs(newInsts)
			}
			results[i] = a
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}

// addrs extracts the addresses of insts.
func addrs(insts []disasm.Inst) []uint64 {
	out := make([]uint64, len(insts))
	for i, in := range insts {
		out[i] = in.Addr
	}
	return out
}

// ops extracts the mnemonics of insts.
func ops(insts []disasm.Inst) []string {
	out := make([]string, len(insts))
	for i, in := range insts {
		out[i] = in.Op
	}
	return out
}

// writeSummary prints the overall comparison: pair counts, total size
// delta, the aggregated opcode delta, and the top-N changed functions.
func writeSummary(w io.Writer, pairs []*fndiff.Pair, analyzed []*analysis, top int, sortBy string) {
	counts := map[fndiff.State]int{}
	var sizeDelta int64
	for _, p := range pairs {
		counts[p.State]++
		sizeDelta += p.SizeDelta()
	}
	noise := 0
	totalOps := fndiff.OpCount{}
	for _, a := range analyzed {
		if a.noise {
			noise++
			continue
		}
		totalOps.Add(a.opDelta)
	}

	fmt.Fprintf(w, "functions: %d identical, %d changed (+%d relocations), %d added, %d removed\n",
		counts[fndiff.StateIdentical], counts[fndiff.StateChanged]-noise, noise,
		counts[fndiff.StateAdded], counts[fndiff.StateRemoved])
	fmt.Fprintf(w, "total text size delta: %+d bytes\n", sizeDelta)

	if len(totalOps) > 0 {
		fmt.Fprintf(w, "\ninstruction delta by opcode:\n")
		for _, op := range sortedOps(totalOps) {
			fmt.Fprintf(w, "  %+6d %s\n", totalOps[op], op)
		}
	}

	writeTop(w, pairs, analyzed, top, sortBy)
}

// sortedOps orders mnemonics by descending |delta|, then name.
func sortedOps(counts fndiff.OpCount) []string {
	ops := make([]string, 0, len(counts))
	for op := range counts {
		ops = append(ops, op)
	}
	slices.SortFunc(ops, func(a, b string) int {
		if d := abs(counts[b]) - abs(counts[a]); d != 0 {
			return d
		}
		return cmp.Compare(a, b)
	})
	return ops
}

// writeTop prints the top-N functions ranked by absolute size or
// instruction-count delta.
func writeTop(w io.Writer, pairs []*fndiff.Pair, analyzed []*analysis, top int, sortBy string) {
	instDelta := map[string]int{}
	for _, a := range analyzed {
		if !a.noise {
			instDelta[a.pair.Name] = a.instDelta
		}
	}

	ranked := make([]*fndiff.Pair, 0, len(pairs))
	for _, p := range pairs {
		if p.State == fndiff.StateIdentical {
			continue
		}
		switch sortBy {
		case "size":
			if p.SizeDelta() == 0 {
				continue
			}
		case "insts":
			if instDelta[p.Name] == 0 {
				continue
			}
		}
		ranked = append(ranked, p)
	}
	slices.SortFunc(ranked, func(a, b *fndiff.Pair) int {
		var d int
		if sortBy == "insts" {
			d = abs(instDelta[b.Name]) - abs(instDelta[a.Name])
		} else {
			d = int(abs64(b.SizeDelta()) - abs64(a.SizeDelta()))
		}
		if d != 0 {
			return d
		}
		return cmp.Compare(a.Name, b.Name)
	})
	if len(ranked) > top {
		ranked = ranked[:top]
	}
	if len(ranked) == 0 {
		return
	}

	fmt.Fprintf(w, "\ntop %d by %s delta:\n", len(ranked), sortBy)
	fmt.Fprintf(w, "  %10s %8s %-9s %s\n", "bytes", "insts", "state", "function")
	for _, p := range ranked {
		insts := "-"
		if d, ok := instDelta[p.Name]; ok {
			insts = fmt.Sprintf("%+d", d)
		}
		fmt.Fprintf(w, "  %+10d %8s %-9s %s\n", p.SizeDelta(), insts, p.State, p.Name)
	}
}

// diffLine is one rendered diff row: an edit with the addresses of
// the instructions it came from, so every line can be cross-referenced
// with objdump or a profiler. oldAddr is zero for inserts and newAddr
// is zero for deletes.
type diffLine struct {
	op               fndiff.Op
	oldAddr, newAddr uint64
	text             string
}

// addr returns the address to display: the old-side one when present.
func (l diffLine) addr() uint64 {
	if l.op == fndiff.OpInsert {
		return l.newAddr
	}
	return l.oldAddr
}

// diffLines resolves the addresses of each edit by walking the edit
// script with one cursor per side.
func diffLines(a *analysis) []diffLine {
	lines := make([]diffLine, len(a.edits))
	oi, ni := 0, 0
	for i, e := range a.edits {
		switch e.Op {
		case fndiff.OpDelete:
			lines[i] = diffLine{e.Op, a.oldAddrs[oi], 0, e.Text}
			oi++
		case fndiff.OpInsert:
			lines[i] = diffLine{e.Op, 0, a.newAddrs[ni], e.Text}
			ni++
		default:
			lines[i] = diffLine{e.Op, a.oldAddrs[oi], a.newAddrs[ni], e.Text}
			oi, ni = oi+1, ni+1
		}
	}
	return lines
}

// hunkContext is how many unchanged lines are kept around each change.
const hunkContext = 3

// hunks splits lines into groups of changes with hunkContext equal
// lines of context, eliding longer equal runs.
func hunks(lines []diffLine) [][]diffLine {
	var out [][]diffLine
	var cur []diffLine
	// pending buffers the equal run since the last change.
	var pending []diffLine
	for _, l := range lines {
		if l.op == fndiff.OpEqual {
			pending = append(pending, l)
			continue
		}
		switch {
		case cur == nil:
			// Start a hunk with trailing context only.
			if len(pending) > hunkContext {
				pending = pending[len(pending)-hunkContext:]
			}
		case len(pending) > 2*hunkContext:
			// The equal run is long enough to split hunks.
			cur = append(cur, pending[:hunkContext]...)
			out = append(out, cur)
			cur = nil
			pending = pending[len(pending)-hunkContext:]
		}
		cur = append(cur, pending...)
		pending = nil
		cur = append(cur, l)
	}
	if cur != nil {
		if len(pending) > hunkContext {
			pending = pending[:hunkContext]
		}
		out = append(out, append(cur, pending...))
	}
	return out
}

// writeFuncDiff prints a unified-style diff of one function, grouped
// into hunks with an address column.
func writeFuncDiff(w io.Writer, a *analysis) {
	p := a.pair
	fmt.Fprintf(w, "--- %s (%d bytes)\n", p.Name, p.Old.Size)
	fmt.Fprintf(w, "+++ %s (%d bytes)\n", p.Name, p.New.Size)
	if a.noise {
		fmt.Fprintf(w, "bytes differ only by relocation; normalized assembly is identical\n")
		return
	}
	for _, hunk := range hunks(diffLines(a)) {
		fmt.Fprintf(w, "@@ %s @@\n", hunkRange(hunk))
		for _, l := range hunk {
			fmt.Fprintf(w, "%c%x: %s\n", " -+"[l.op], l.addr(), l.text)
		}
	}
}

// hunkRange describes a hunk by the first old- and new-side addresses
// it covers.
func hunkRange(hunk []diffLine) string {
	var oldAddr, newAddr uint64
	for _, l := range hunk {
		if oldAddr == 0 && l.oldAddr != 0 {
			oldAddr = l.oldAddr
		}
		if newAddr == 0 && l.newAddr != 0 {
			newAddr = l.newAddr
		}
	}
	return fmt.Sprintf("-%x +%x", oldAddr, newAddr)
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
