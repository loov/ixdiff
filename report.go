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

// writeFuncDiff prints a unified-style diff of one function.
func writeFuncDiff(w io.Writer, a *analysis) {
	p := a.pair
	fmt.Fprintf(w, "--- %s (%d bytes)\n", p.Name, p.Old.Size)
	fmt.Fprintf(w, "+++ %s (%d bytes)\n", p.Name, p.New.Size)
	if a.noise {
		fmt.Fprintf(w, "bytes differ only by relocation; normalized assembly is identical\n")
		return
	}
	for _, e := range a.edits {
		switch e.Op {
		case fndiff.OpDelete:
			fmt.Fprintf(w, "-%s\n", e.Text)
		case fndiff.OpInsert:
			fmt.Fprintf(w, "+%s\n", e.Text)
		default:
			fmt.Fprintf(w, " %s\n", e.Text)
		}
	}
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
