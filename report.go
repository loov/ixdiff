package main

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

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
func analyze(pairs []*fndiff.Pair, old, new *objfile.Binary, limit int, opts disasm.Options) ([]*analysis, error) {
	oldLookup, newLookup := disasm.Lookup(old), disasm.Lookup(new)

	results := make([]*analysis, len(pairs))
	var g errgroup.Group
	g.SetLimit(limit)
	for i, p := range pairs {
		g.Go(func() error {
			if p.State == fndiff.StateChanged &&
				disasm.RelocOnly(old.Arch, p.Old.Code(), p.New.Code(),
					p.Old.Addr, p.New.Addr, oldLookup, newLookup, old.DataSym, new.DataSym) {
				// Provably relocation-only: skip disassembly.
				results[i] = &analysis{pair: p, noise: true}
				return nil
			}

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

			a := &analysis{
				pair:      p,
				instDelta: countInsts(newInsts) - countInsts(oldInsts),
				opDelta:   fndiff.CountOps(ops(oldInsts)).Delta(fndiff.CountOps(ops(newInsts))),
			}
			if p.State == fndiff.StateChanged {
				oldOpts, newOpts := opts, opts
				oldOpts.IsAddr, newOpts.IsAddr = old.Contains, new.Contains
				oldOpts.DataSym, newOpts.DataSym = old.DataSym, new.DataSym
				oldLines, newLines := alignLabels(
					disasm.NormalizeLines(p.Old.Name, oldInsts, oldOpts),
					disasm.NormalizeLines(p.New.Name, newInsts, newOpts))
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

// bodySimilar returns the rename-detection predicate: two functions
// from the same package with sizes within 20% whose normalized bodies
// are at least 90% identical lines.
func bodySimilar(old, new *objfile.Binary, opts disasm.Options) func(oldF, newF *objfile.Func) bool {
	oldLookup, newLookup := disasm.Lookup(old), disasm.Lookup(new)
	return func(oldF, newF *objfile.Func) bool {
		small, large := oldF.Size, newF.Size
		if small > large {
			small, large = large, small
		}
		if small*5 < large*4 || pkgOf(oldF.Name) != pkgOf(newF.Name) {
			return false
		}

		oldInsts, err := disasm.Decode(old.Arch, oldF.Code(), oldF.Addr, oldLookup)
		if err != nil {
			return false
		}
		newInsts, err := disasm.Decode(new.Arch, newF.Code(), newF.Addr, newLookup)
		if err != nil {
			return false
		}
		oldOpts, newOpts := opts, opts
		oldOpts.IsAddr, newOpts.IsAddr = old.Contains, new.Contains
		oldOpts.DataSym, newOpts.DataSym = old.DataSym, new.DataSym
		// Each side normalizes under its own symbol name so
		// self-referencing branches become labels on both sides and a
		// pure rename compares equal.
		oldLines := disasm.Normalize(oldF.Name, oldInsts, oldOpts)
		newLines := disasm.Normalize(newF.Name, newInsts, newOpts)

		equal := 0
		for _, e := range fndiff.Diff(oldLines, newLines) {
			if e.Op == fndiff.OpEqual {
				equal++
			}
		}
		return equal*10 >= max(len(oldLines), len(newLines))*9
	}
}

// listing builds an all-insert (added) or all-delete (removed)
// analysis so single-sided functions can render as a full assembly
// listing in --fn mode.
func listing(p *fndiff.Pair, old, new *objfile.Binary, opts disasm.Options) (*analysis, error) {
	fn, bin, op := p.New, new, fndiff.OpInsert
	if p.State == fndiff.StateRemoved {
		fn, bin, op = p.Old, old, fndiff.OpDelete
	}
	insts, err := disasm.Decode(bin.Arch, fn.Code(), fn.Addr, disasm.Lookup(bin))
	if err != nil {
		return nil, fmt.Errorf("disassembling %s: %w", p.Name, err)
	}
	opts.IsAddr = bin.Contains
	opts.DataSym = bin.DataSym
	a := &analysis{pair: p}
	for _, text := range disasm.Normalize(fn.Name, insts, opts) {
		a.edits = append(a.edits, fndiff.Edit{Op: op, Text: text})
	}
	if op == fndiff.OpInsert {
		a.newAddrs = addrs(insts)
		a.instDelta = countInsts(insts)
		a.opDelta = fndiff.OpCount{}.Delta(fndiff.CountOps(ops(insts)))
	} else {
		a.oldAddrs = addrs(insts)
		a.instDelta = -countInsts(insts)
		a.opDelta = fndiff.CountOps(ops(insts)).Delta(fndiff.OpCount{})
	}
	return a, nil
}

// alignLabels renders both sides of a changed function with branch
// labels derived from an instruction alignment, so that a branch whose
// target is structurally unchanged gets the same label on both sides
// no matter how many instructions were inserted or removed elsewhere.
//
// It first aligns the two sides with all labels masked, then names
// aligned target pairs identically (numbered in new-side order) and
// falls back to fresh per-side numbers for targets that do not align —
// those branches genuinely changed and should diff.
func alignLabels(old, new []disasm.Line) (oldLines, newLines []string) {
	masked := func(int) string { return "L?" }
	align := fndiff.Diff(disasm.Render(old, masked), disasm.Render(new, masked))

	// oldToNew maps aligned instruction indices via the equal lines.
	oldToNew := make(map[int]int)
	oi, ni := 0, 0
	for _, e := range align {
		switch e.Op {
		case fndiff.OpDelete:
			oi++
		case fndiff.OpInsert:
			ni++
		default:
			oldToNew[oi] = ni
			oi, ni = oi+1, ni+1
		}
	}

	// New-side targets are numbered in address order; old-side targets
	// inherit the number of the new target they align to, and the rest
	// continue the numbering in old order.
	newNumber := targetNumbers(new, 0)
	next := len(newNumber)
	oldNumber := make(map[int]int)
	for _, t := range sortedTargets(old) {
		if nt, ok := oldToNew[t]; ok {
			if num, ok := newNumber[nt]; ok {
				oldNumber[t] = num
				continue
			}
		}
		next++
		oldNumber[t] = next
	}

	label := func(number map[int]int) func(int) string {
		return func(target int) string { return "L" + strconv.Itoa(number[target]) }
	}
	return disasm.Render(old, label(oldNumber)), disasm.Render(new, label(newNumber))
}

// sortedTargets returns the distinct branch targets of lines in
// address order.
func sortedTargets(lines []disasm.Line) []int {
	seen := map[int]bool{}
	var targets []int
	for _, l := range lines {
		if l.Target >= 0 && !seen[l.Target] {
			seen[l.Target] = true
			targets = append(targets, l.Target)
		}
	}
	slices.Sort(targets)
	return targets
}

// targetNumbers numbers the distinct targets of lines starting at
// base+1.
func targetNumbers(lines []disasm.Line, base int) map[int]int {
	number := make(map[int]int)
	for i, t := range sortedTargets(lines) {
		number[t] = base + i + 1
	}
	return number
}

// addrs extracts the addresses of insts.
func addrs(insts []disasm.Inst) []uint64 {
	out := make([]uint64, len(insts))
	for i, in := range insts {
		out[i] = in.Addr
	}
	return out
}

// ops extracts the mnemonics of insts, skipping BYTE pseudo-
// instructions: padding is not code and would pollute the statistics.
func ops(insts []disasm.Inst) []string {
	out := make([]string, 0, len(insts))
	for _, in := range insts {
		if in.Op != "BYTE" {
			out = append(out, in.Op)
		}
	}
	return out
}

// countInsts counts real instructions, excluding BYTE padding.
func countInsts(insts []disasm.Inst) int {
	n := 0
	for _, in := range insts {
		if in.Op != "BYTE" {
			n++
		}
	}
	return n
}

// writeSummary prints the overall comparison: pair counts, total size
// delta, the aggregated opcode delta, and the top-N changed functions.
func writeSummary(w io.Writer, pairs []*fndiff.Pair, analyzed []*analysis, top int, sortBy string, states map[fndiff.State]bool) {
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
	totalOps.Compact()

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

	if rollup := pkgRollup(pairs, analyzed); len(rollup) > 0 {
		fmt.Fprintf(w, "\npackage delta:\n")
		fmt.Fprintf(w, "  %10s %8s %8s %6s %8s  %s\n",
			"bytes", "insts", "changed", "added", "removed", "package")
		for _, d := range rollup {
			fmt.Fprintf(w, "  %+10d %+8d %8d %6d %8d  %s\n",
				d.SizeDelta, d.InstDelta, d.Changed, d.Added, d.Removed, d.Name)
		}
	}

	writeTop(w, pairs, analyzed, top, sortBy, states)
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

// instDeltas collects the instruction-count delta of every analyzed
// function that is not relocation-only noise.
func instDeltas(analyzed []*analysis) map[string]int {
	deltas := map[string]int{}
	for _, a := range analyzed {
		if !a.noise {
			deltas[a.pair.Name] = a.instDelta
		}
	}
	return deltas
}

// rankPairs returns the top non-identical functions ordered by
// absolute size or instruction-count delta, or by name; zero-delta
// entries are omitted. A non-nil states set keeps only those states.
func rankPairs(pairs []*fndiff.Pair, instDelta map[string]int, top int, sortBy string, states map[fndiff.State]bool) []*fndiff.Pair {
	ranked := make([]*fndiff.Pair, 0, len(pairs))
	for _, p := range pairs {
		if p.State == fndiff.StateIdentical {
			continue
		}
		if states != nil && !states[p.State] {
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
		case "name":
			if p.SizeDelta() == 0 && instDelta[p.Name] == 0 {
				continue
			}
		}
		ranked = append(ranked, p)
	}
	slices.SortFunc(ranked, func(a, b *fndiff.Pair) int {
		var d int
		switch sortBy {
		case "insts":
			d = abs(instDelta[b.Name]) - abs(instDelta[a.Name])
		case "name":
		default:
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
	return ranked
}

// writeTop prints the top-N functions ranked by absolute size or
// instruction-count delta.
func writeTop(w io.Writer, pairs []*fndiff.Pair, analyzed []*analysis, top int, sortBy string, states map[fndiff.State]bool) {
	instDelta := instDeltas(analyzed)
	ranked := rankPairs(pairs, instDelta, top, sortBy, states)
	if len(ranked) == 0 {
		return
	}

	order := sortBy + " delta"
	if sortBy == "name" {
		order = "name"
	}
	fmt.Fprintf(w, "\ntop %d by %s:\n", len(ranked), order)
	fmt.Fprintf(w, "  %10s %8s %-9s %s\n", "bytes", "insts", "state", "function")
	for _, p := range ranked {
		insts := "-"
		if d, ok := instDelta[p.Name]; ok {
			insts = fmt.Sprintf("%+d", d)
		}
		name := p.Name
		if p.RenamedFrom != "" {
			name += " (was " + p.RenamedFrom + ")"
		}
		fmt.Fprintf(w, "  %+10d %8s %-9s %s\n", p.SizeDelta(), insts, p.State, name)
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
func writeFuncDiff(w io.Writer, a *analysis, pal palette) {
	writeDiffHeader(w, a.pair)
	if a.noise {
		fmt.Fprintf(w, "bytes differ only by relocation; normalized assembly is identical\n")
		return
	}
	writeHunks(w, a, pal)
}

// writeHunks renders the hunked, aligned, emphasized edit script of a.
func writeHunks(w io.Writer, a *analysis, pal palette) {
	for _, hunk := range hunks(diffLines(a)) {
		fmt.Fprintln(w, pal.paint(pal.hunk, fmt.Sprintf("@@ %s @@", hunkRange(hunk))))
		texts := make([]string, len(hunk))
		for i, l := range hunk {
			texts[i] = l.text
		}
		aligned := alignOps(texts)
		emphasized := emphasize(hunk, aligned, pal)
		for i, text := range aligned {
			if e, ok := emphasized[&hunk[i]]; ok {
				text = e
			}
			line := fmt.Sprintf("%c%x: %s", " -+"[hunk[i].op], hunk[i].addr(), text)
			switch hunk[i].op {
			case fndiff.OpDelete:
				line = pal.paint(pal.del, line)
			case fndiff.OpInsert:
				line = pal.paint(pal.ins, line)
			}
			fmt.Fprintln(w, line)
		}
	}
}

// emphasize pairs each run of deletions with the following run of
// insertions and, when the paired lines share their shape, returns
// replacement texts with only the differing operands emphasized.
func emphasize(hunk []diffLine, aligned []string, pal palette) map[*diffLine]string {
	if pal.emph == "" {
		return nil
	}
	alignedOf := make(map[*diffLine]string, len(hunk))
	for i := range hunk {
		alignedOf[&hunk[i]] = aligned[i]
	}
	out := map[*diffLine]string{}
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
func writeDiffHeader(w io.Writer, p *fndiff.Pair) {
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

// sideRow pairs an old-side and new-side line for two-column output.
// Either side may be nil when the row has no counterpart.
type sideRow struct {
	old, new *diffLine
}

// sideRows pairs the lines of a hunk: equal lines share a row, and a
// run of deletions zips with the following run of insertions so
// replaced instructions sit next to each other.
func sideRows(hunk []diffLine) []sideRow {
	var rows []sideRow
	for i := 0; i < len(hunk); {
		if hunk[i].op == fndiff.OpEqual {
			rows = append(rows, sideRow{&hunk[i], &hunk[i]})
			i++
			continue
		}
		var dels, inss []*diffLine
		for ; i < len(hunk) && hunk[i].op == fndiff.OpDelete; i++ {
			dels = append(dels, &hunk[i])
		}
		for ; i < len(hunk) && hunk[i].op == fndiff.OpInsert; i++ {
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
func writeFuncDiffSide(w io.Writer, a *analysis, pal palette) {
	writeDiffHeader(w, a.pair)
	if a.noise {
		fmt.Fprintf(w, "bytes differ only by relocation; normalized assembly is identical\n")
		return
	}
	for _, hunk := range hunks(diffLines(a)) {
		fmt.Fprintln(w, pal.paint(pal.hunk, fmt.Sprintf("@@ %s @@", hunkRange(hunk))))

		texts := make([]string, len(hunk))
		for i, l := range hunk {
			texts[i] = l.text
		}
		aligned := alignOps(texts)
		alignedOf := make(map[*diffLine]string, len(hunk))
		for i := range hunk {
			alignedOf[&hunk[i]] = aligned[i]
		}
		emphasized := emphasize(hunk, aligned, pal)
		// plain renders one side of a row with that side's address,
		// without escape codes; all width math uses it. show adds the
		// operand emphasis unless the cell was truncated.
		plain := func(l *diffLine, addr uint64) string {
			if l == nil {
				return ""
			}
			s := fmt.Sprintf("%x: %s", addr, alignedOf[l])
			if len(s) > sideColumnWidth {
				s = s[:sideColumnWidth-3] + "..."
			}
			return s
		}
		show := func(l *diffLine, addr uint64) string {
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
				width = max(width, len(plain(row.old, row.old.oldAddr)))
			}
		}
		for _, row := range rows {
			var left, right string
			pad := width
			marker := ' '
			if row.old != nil {
				left = show(row.old, row.old.oldAddr)
				pad = width - len(plain(row.old, row.old.oldAddr))
			}
			if row.new != nil {
				right = show(row.new, row.new.newAddr)
			}
			switch {
			case row.old != nil && row.old.op == fndiff.OpDelete && row.new != nil:
				marker = '|'
			case row.old != nil && row.old.op == fndiff.OpDelete:
				marker = '<'
			case row.new != nil && row.new.op == fndiff.OpInsert:
				marker = '>'
			}
			// Pad by visible length, then paint: escape codes must
			// not count toward the column width.
			left += strings.Repeat(" ", pad)
			if row.old != nil && row.old.op == fndiff.OpDelete {
				left = pal.paint(pal.del, left)
			}
			if row.new != nil && row.new.op == fndiff.OpInsert {
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
