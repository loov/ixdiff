package fndiff

import (
	"slices"
	"strconv"

	"github.com/loov/ixdiff/internal/norm"
)

// AlignLabels renders both sides of a changed function with branch
// labels derived from an instruction alignment, so that a branch whose
// target is structurally unchanged gets the same label on both sides
// no matter how many instructions were inserted or removed elsewhere.
//
// It first aligns the two sides with all labels masked, then names
// aligned target pairs identically (numbered in new-side order) and
// falls back to fresh per-side numbers for targets that do not align —
// those branches genuinely changed and should diff.
func AlignLabels(old, new []norm.Line) (oldLines, newLines []string) {
	masked := func(int) string { return "L?" }
	align := Diff(norm.Render(old, masked), norm.Render(new, masked))

	// oldToNew maps aligned instruction indices via the equal lines.
	oldToNew := make(map[int]int)
	oi, ni := 0, 0
	for _, e := range align {
		switch e.Op {
		case OpDelete:
			oi++
		case OpInsert:
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
	return norm.Render(old, label(oldNumber)), norm.Render(new, label(newNumber))
}

// sortedTargets returns the distinct branch targets of lines in
// address order.
func sortedTargets(lines []norm.Line) []int {
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
func targetNumbers(lines []norm.Line, base int) map[int]int {
	number := make(map[int]int)
	for i, t := range sortedTargets(lines) {
		number[t] = base + i + 1
	}
	return number
}
