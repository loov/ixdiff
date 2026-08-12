package main

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/loov/ixdiff/internal/fndiff"
	"github.com/loov/ixdiff/ixdiff"
)

// displayState renders a pair state for tables and JSON. Relocation-
// only pairs display as "changed": the distinction is reported
// separately (the "+N relocations" count, the relocation_only JSON
// field, and the in-diff note).
func displayState(s ixdiff.State) string {
	if s == ixdiff.RelocationOnly {
		return "changed"
	}
	return s.String()
}

// resolveLines resolves the addresses of an edit script into printable
// diff lines; used by the --blocks path, whose edits are computed in
// main rather than by the library.
func resolveLines(edits []fndiff.Edit, oldAddrs, newAddrs []uint64) []ixdiff.Line {
	resolved := fndiff.ResolveLines(edits, oldAddrs, newAddrs)
	out := make([]ixdiff.Line, len(resolved))
	for i, l := range resolved {
		out[i] = ixdiff.Line{Op: ixdiff.EditOp(l.Op), OldAddr: l.OldAddr, NewAddr: l.NewAddr, Text: l.Text}
	}
	return out
}

// pkgRollupCap bounds the package table; packages beyond it are rare
// stragglers with tiny deltas.
const pkgRollupCap = 20

// cappedPackages is the package rollup limited to pkgRollupCap rows
// for presentation.
func cappedPackages(pairs []ixdiff.Pair) []ixdiff.PackageDelta {
	rollup := ixdiff.PackageDeltas(pairs)
	if len(rollup) > pkgRollupCap {
		rollup = rollup[:pkgRollupCap]
	}
	return rollup
}

// writeSummary prints the overall comparison: pair counts, total size
// delta, the aggregated opcode delta, and the top-N changed functions.
func writeSummary(w io.Writer, pairs []ixdiff.Pair, top int, sortBy string, states map[ixdiff.State]bool) {
	counts := map[ixdiff.State]int{}
	var sizeDelta int64
	spillDelta, slotDelta := 0, 0
	totalOps := ixdiff.OpCount{}
	for _, p := range pairs {
		counts[p.State]++
		sizeDelta += p.SizeDelta
		spillDelta += p.SpillDelta
		slotDelta += p.SlotDelta
		totalOps.Add(p.OpDelta)
	}
	totalOps.Compact()

	fmt.Fprintf(w, "functions: %d identical, %d changed (+%d relocations), %d added, %d removed\n",
		counts[ixdiff.Identical], counts[ixdiff.Changed], counts[ixdiff.RelocationOnly],
		counts[ixdiff.Added], counts[ixdiff.Removed])
	fmt.Fprintf(w, "total text size delta: %+d bytes\n", sizeDelta)
	fmt.Fprintf(w, "total spill delta: %+d registers moved\n", spillDelta)
	fmt.Fprintf(w, "total stack traffic delta: %+d 8-byte slots\n", slotDelta)

	if len(totalOps) > 0 {
		fmt.Fprintf(w, "\ninstruction delta by opcode:\n")
		for _, op := range sortedOps(totalOps) {
			fmt.Fprintf(w, "  %+6d %s\n", totalOps[op], op)
		}
	}

	if rollup := cappedPackages(pairs); len(rollup) > 0 {
		fmt.Fprintf(w, "\npackage delta:\n")
		fmt.Fprintf(w, "  %10s %8s %8s %8s %8s %6s %8s  %s\n",
			"bytes", "insts", "spills", "slots", "changed", "added", "removed", "package")
		for _, d := range rollup {
			fmt.Fprintf(w, "  %+10d %+8d %+8d %+8d %8d %6d %8d  %s\n",
				d.SizeDelta, d.InstDelta, d.SpillDelta, d.SlotDelta, d.Changed, d.Added, d.Removed, d.Name)
		}
	}

	writeTop(w, pairs, top, sortBy, states)
}

// sortedOps orders mnemonics by descending |delta|, then name.
func sortedOps(counts ixdiff.OpCount) []string {
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

// rankPairs returns the top non-identical functions ordered by
// absolute size or instruction-count delta, or by name; zero-delta
// entries are omitted. A non-nil states set keeps only those states.
func rankPairs(pairs []ixdiff.Pair, top int, sortBy string, states map[ixdiff.State]bool) []ixdiff.Pair {
	ranked := make([]ixdiff.Pair, 0, len(pairs))
	for _, p := range pairs {
		if p.State == ixdiff.Identical {
			continue
		}
		if states != nil && !states[p.State] {
			continue
		}
		switch sortBy {
		case "size":
			if p.SizeDelta == 0 {
				continue
			}
		case "insts":
			if p.InstDelta == 0 {
				continue
			}
		case "spills":
			if p.SpillDelta == 0 {
				continue
			}
		case "slots":
			if p.SlotDelta == 0 {
				continue
			}
		case "name":
			if p.SizeDelta == 0 && p.InstDelta == 0 && p.SpillDelta == 0 && p.SlotDelta == 0 {
				continue
			}
		}
		ranked = append(ranked, p)
	}
	slices.SortFunc(ranked, func(a, b ixdiff.Pair) int {
		var d int
		switch sortBy {
		case "insts":
			d = abs(b.InstDelta) - abs(a.InstDelta)
		case "spills":
			d = abs(b.SpillDelta) - abs(a.SpillDelta)
		case "slots":
			d = abs(b.SlotDelta) - abs(a.SlotDelta)
		case "name":
		default:
			d = int(abs64(b.SizeDelta) - abs64(a.SizeDelta))
		}
		if d != 0 {
			return d
		}
		return cmp.Compare(a.Name, b.Name)
	})
	if len(ranked) > top {
		ranked = ranked[:top]
	}
	return ranked
}

// writeTop prints the top-N functions ranked by absolute size or
// instruction-count delta.
func writeTop(w io.Writer, pairs []ixdiff.Pair, top int, sortBy string, states map[ixdiff.State]bool) {
	ranked := rankPairs(pairs, top, sortBy, states)
	if len(ranked) == 0 {
		return
	}

	order := sortBy + " delta"
	if sortBy == "name" {
		order = "name"
	}
	fmt.Fprintf(w, "\ntop %d by %s:\n", len(ranked), order)
	fmt.Fprintf(w, "  %10s %8s %8s %8s %-9s %s\n", "bytes", "insts", "spills", "slots", "state", "function")
	for _, p := range ranked {
		insts, spills, slots := "-", "-", "-"
		if p.State != ixdiff.RelocationOnly {
			insts = fmt.Sprintf("%+d", p.InstDelta)
			spills = fmt.Sprintf("%+d", p.SpillDelta)
			slots = fmt.Sprintf("%+d", p.SlotDelta)
		}
		name := p.Name
		if p.RenamedFrom != "" {
			name += " (was " + p.RenamedFrom + ")"
		}
		fmt.Fprintf(w, "  %+10d %8s %8s %8s %-9s %s\n", p.SizeDelta, insts, spills, slots, displayState(p.State), name)
	}
}

// lineAddr returns the address to display for a diff line: the
// old-side one when present.
func lineAddr(l ixdiff.Line) uint64 {
	if l.Op == ixdiff.Insert {
		return l.NewAddr
	}
	return l.OldAddr
}

// hunkContext is how many unchanged lines are kept around each change.
const hunkContext = 3

// hunks splits lines into groups of changes with hunkContext equal
// lines of context, eliding longer equal runs.
func hunks(lines []ixdiff.Line) [][]ixdiff.Line {
	var out [][]ixdiff.Line
	var cur []ixdiff.Line
	// pending buffers the equal run since the last change.
	var pending []ixdiff.Line
	for _, l := range lines {
		if l.Op == ixdiff.Equal {
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
func writeFuncDiff(w io.Writer, p ixdiff.Pair, lines []ixdiff.Line, pal palette) {
	writeDiffHeader(w, p)
	if p.State == ixdiff.RelocationOnly {
		fmt.Fprintf(w, "bytes differ only by relocation; normalized assembly is identical\n")
		return
	}
	writeHunks(w, lines, pal)
}

// writeHunks renders the hunked, aligned, emphasized edit script.
func writeHunks(w io.Writer, lines []ixdiff.Line, pal palette) {
	for _, hunk := range hunks(lines) {
		fmt.Fprintln(w, pal.paint(pal.hunk, fmt.Sprintf("@@ %s @@", hunkRange(hunk))))
		texts := make([]string, len(hunk))
		for i, l := range hunk {
			texts[i] = l.Text
		}
		aligned := alignOps(texts)
		emphasized := emphasize(hunk, aligned, pal)
		for i, text := range aligned {
			if e, ok := emphasized[&hunk[i]]; ok {
				text = e
			}
			line := fmt.Sprintf("%c%x: %s", " -+"[hunk[i].Op], lineAddr(hunk[i]), text)
			switch hunk[i].Op {
			case ixdiff.Delete:
				line = pal.paint(pal.del, line)
			case ixdiff.Insert:
				line = pal.paint(pal.ins, line)
			}
			fmt.Fprintln(w, line)
		}
	}
}

// emphasize pairs each run of deletions with the following run of
// insertions and, when the paired lines share their shape, returns
// replacement texts with only the differing operands emphasized.
func emphasize(hunk []ixdiff.Line, aligned []string, pal palette) map[*ixdiff.Line]string {
	if pal.emph == "" {
		return nil
	}
	alignedOf := make(map[*ixdiff.Line]string, len(hunk))
	for i := range hunk {
		alignedOf[&hunk[i]] = aligned[i]
	}
	out := map[*ixdiff.Line]string{}
	for _, row := range sideRows(hunk) {
		if row.old == nil || row.new == nil || row.old == row.new {
			continue
		}
		oldText, newText, ok := pal.emphasizeDiff(alignedOf[row.old], alignedOf[row.new])
		if ok {
			out[row.old] = oldText
			out[row.new] = newText
		}
	}
	return out
}

// maxOpWidth caps the mnemonic column so one unusually long mnemonic
// does not push every operand far right.
const maxOpWidth = 8

// alignOps pads mnemonics to a common column so operands line up,
// objdump-style. The column is the longest mnemonic in the group,
// capped at maxOpWidth.
func alignOps(texts []string) []string {
	width := 0
	for _, text := range texts {
		if op, _, ok := strings.Cut(text, " "); ok {
			width = max(width, min(len(op), maxOpWidth))
		}
	}
	out := make([]string, len(texts))
	for i, text := range texts {
		op, args, ok := strings.Cut(text, " ")
		if !ok || len(op) >= width {
			out[i] = text
			continue
		}
		out[i] = op + strings.Repeat(" ", width-len(op)+1) + args
	}
	return out
}

// writeDiffHeader prints the ---/+++ header; an absent side (added or
// removed function) is marked as such.
func writeDiffHeader(w io.Writer, p ixdiff.Pair) {
	if p.Old != nil {
		fmt.Fprintf(w, "--- %s (%d bytes)\n", p.Old.Name, p.Old.Size)
	} else {
		fmt.Fprintf(w, "--- %s (absent)\n", p.Name)
	}
	if p.New != nil {
		fmt.Fprintf(w, "+++ %s (%d bytes)\n", p.Name, p.New.Size)
	} else {
		fmt.Fprintf(w, "+++ %s (absent)\n", p.Name)
	}
}

// hunkRange describes a hunk by the first old- and new-side addresses
// it covers.
func hunkRange(hunk []ixdiff.Line) string {
	var oldAddr, newAddr uint64
	for _, l := range hunk {
		if oldAddr == 0 && l.OldAddr != 0 {
			oldAddr = l.OldAddr
		}
		if newAddr == 0 && l.NewAddr != 0 {
			newAddr = l.NewAddr
		}
	}
	return fmt.Sprintf("-%x +%x", oldAddr, newAddr)
}

// sideRow pairs an old-side and new-side line for two-column output.
// Either side may be nil when the row has no counterpart.
type sideRow struct {
	old, new *ixdiff.Line
}

// sideRows pairs the lines of a hunk: equal lines share a row, and a
// run of deletions zips with the following run of insertions so
// replaced instructions sit next to each other.
func sideRows(hunk []ixdiff.Line) []sideRow {
	var rows []sideRow
	for i := 0; i < len(hunk); {
		if hunk[i].Op == ixdiff.Equal {
			rows = append(rows, sideRow{&hunk[i], &hunk[i]})
			i++
			continue
		}
		var dels, inss []*ixdiff.Line
		for ; i < len(hunk) && hunk[i].Op == ixdiff.Delete; i++ {
			dels = append(dels, &hunk[i])
		}
		for ; i < len(hunk) && hunk[i].Op == ixdiff.Insert; i++ {
			inss = append(inss, &hunk[i])
		}
		for j := range max(len(dels), len(inss)) {
			var row sideRow
			if j < len(dels) {
				row.old = dels[j]
			}
			if j < len(inss) {
				row.new = inss[j]
			}
			rows = append(rows, row)
		}
	}
	return rows
}

// sideColumnWidth caps each column so two columns fit a wide terminal.
const sideColumnWidth = 60

// writeFuncDiffSide prints the diff of one function as two columns,
// old on the left and new on the right, with a marker column between:
// space for unchanged rows, < for deletions, > for insertions, and |
// for replacements.
func writeFuncDiffSide(w io.Writer, p ixdiff.Pair, lines []ixdiff.Line, pal palette) {
	writeDiffHeader(w, p)
	if p.State == ixdiff.RelocationOnly {
		fmt.Fprintf(w, "bytes differ only by relocation; normalized assembly is identical\n")
		return
	}
	writeHunksSide(w, lines, pal)
}

// writeHunksSide renders the hunked edit script as two columns.
func writeHunksSide(w io.Writer, lines []ixdiff.Line, pal palette) {
	for _, hunk := range hunks(lines) {
		fmt.Fprintln(w, pal.paint(pal.hunk, fmt.Sprintf("@@ %s @@", hunkRange(hunk))))

		texts := make([]string, len(hunk))
		for i, l := range hunk {
			texts[i] = l.Text
		}
		aligned := alignOps(texts)
		alignedOf := make(map[*ixdiff.Line]string, len(hunk))
		for i := range hunk {
			alignedOf[&hunk[i]] = aligned[i]
		}
		emphasized := emphasize(hunk, aligned, pal)
		// plain renders one side of a row with that side's address,
		// without escape codes; all width math uses it. show adds the
		// operand emphasis unless the cell was truncated.
		plain := func(l *ixdiff.Line, addr uint64) string {
			if l == nil {
				return ""
			}
			s := fmt.Sprintf("%x: %s", addr, alignedOf[l])
			if len(s) > sideColumnWidth {
				s = s[:sideColumnWidth-3] + "..."
			}
			return s
		}
		show := func(l *ixdiff.Line, addr uint64) string {
			s := plain(l, addr)
			if e, ok := emphasized[l]; ok && !strings.HasSuffix(s, "...") {
				return fmt.Sprintf("%x: %s", addr, e)
			}
			return s
		}

		rows := sideRows(hunk)
		width := 0
		for _, row := range rows {
			if row.old != nil {
				width = max(width, len(plain(row.old, row.old.OldAddr)))
			}
		}
		for _, row := range rows {
			var left, right string
			pad := width
			marker := ' '
			if row.old != nil {
				left = show(row.old, row.old.OldAddr)
				pad = width - len(plain(row.old, row.old.OldAddr))
			}
			if row.new != nil {
				right = show(row.new, row.new.NewAddr)
			}
			switch {
			case row.old != nil && row.old.Op == ixdiff.Delete && row.new != nil:
				marker = '|'
			case row.old != nil && row.old.Op == ixdiff.Delete:
				marker = '<'
			case row.new != nil && row.new.Op == ixdiff.Insert:
				marker = '>'
			}
			// Pad by visible length, then paint: escape codes must
			// not count toward the column width.
			left += strings.Repeat(" ", pad)
			if row.old != nil && row.old.Op == ixdiff.Delete {
				left = pal.paint(pal.del, left)
			}
			if row.new != nil && row.new.Op == ixdiff.Insert {
				right = pal.paint(pal.ins, right)
			}
			fmt.Fprintf(w, "%s %c %s\n", left, marker, right)
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
