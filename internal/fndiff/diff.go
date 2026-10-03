package fndiff

import "sort"

// Op is the kind of a diff edit.
type Op int

// The edit kinds. OpEqual keeps a line, OpDelete removes a line from
// the old side, OpInsert adds a line on the new side.
const (
	OpEqual Op = iota
	OpDelete
	OpInsert
)

// Edit is one line of a computed diff.
type Edit struct {
	Op   Op
	Text string
}

// Line is one edit with the addresses of the instructions it came
// from, so every diff line can be cross-referenced with objdump or a
// profiler. OldAddr is zero for inserts and NewAddr is zero for
// deletes.
type Line struct {
	Op               Op
	OldAddr, NewAddr uint64
	Text             string
}

// ResolveLines resolves the addresses of each edit by walking the edit
// script with one cursor per side. oldAddrs and newAddrs are the
// instruction addresses backing the two sides of edits.
func ResolveLines(edits []Edit, oldAddrs, newAddrs []uint64) []Line {
	lines := make([]Line, len(edits))
	oi, ni := 0, 0
	for i, e := range edits {
		switch e.Op {
		case OpDelete:
			lines[i] = Line{e.Op, oldAddrs[oi], 0, e.Text}
			oi++
		case OpInsert:
			lines[i] = Line{e.Op, 0, newAddrs[ni], e.Text}
			ni++
		default:
			lines[i] = Line{e.Op, oldAddrs[oi], newAddrs[ni], e.Text}
			oi, ni = oi+1, ni+1
		}
	}
	return lines
}

// maxLCSCells bounds the table of one exact LCS diff: 16 MiB of
// int32 cells. Larger regions are first split at anchor lines.
const maxLCSCells = 1 << 22

// Diff computes a line diff from a to b. Equal inputs produce
// all-OpEqual output.
//
// Regions small enough for an exact longest-common-subsequence table
// get a minimal diff. Larger ones are split patience-style at lines
// occurring exactly once on each side, and a large region without
// such lines degrades to a full replacement. Memory stays bounded by
// maxLCSCells however large the functions are; an unbounded table
// needed tens of gigabytes for changed multi-megabyte init functions.
func Diff(a, b []string) []Edit {
	return appendDiff(make([]Edit, 0, max(len(a), len(b))), a, b)
}

// appendDiff appends the diff of a and b to edits.
func appendDiff(edits []Edit, a, b []string) []Edit {
	// Trim the common prefix and suffix; for assembly diffs they are
	// usually most of the function.
	var prefix, suffix int
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	for suffix < len(a)-prefix && suffix < len(b)-prefix &&
		a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}

	for _, line := range a[:prefix] {
		edits = append(edits, Edit{OpEqual, line})
	}
	midA, midB := a[prefix:len(a)-suffix], b[prefix:len(b)-suffix]
	if len(midA)*len(midB) <= maxLCSCells {
		edits = appendLCS(edits, midA, midB)
	} else {
		edits = appendAnchored(edits, midA, midB)
	}
	for _, line := range a[len(a)-suffix:] {
		edits = append(edits, Edit{OpEqual, line})
	}
	return edits
}

// appendAnchored diffs a and b by matching the longest in-order run
// of lines that occur exactly once on each side, then diffing the gaps
// between those anchors. Without anchors the region is replaced
// wholesale.
func appendAnchored(edits []Edit, a, b []string) []Edit {
	type count struct{ a, b, bIndex int }
	counts := make(map[string]count, len(a))
	for _, line := range a {
		c := counts[line]
		c.a++
		counts[line] = c
	}
	for i, line := range b {
		if c, ok := counts[line]; ok {
			c.b++
			c.bIndex = i
			counts[line] = c
		}
	}
	var aIndex, bIndex []int
	for i, line := range a {
		if c := counts[line]; c.a == 1 && c.b == 1 {
			aIndex = append(aIndex, i)
			bIndex = append(bIndex, c.bIndex)
		}
	}

	ai, bi := 0, 0
	for _, k := range LongestIncreasing(bIndex) {
		edits = appendDiff(edits, a[ai:aIndex[k]], b[bi:bIndex[k]])
		edits = append(edits, Edit{OpEqual, a[aIndex[k]]})
		ai, bi = aIndex[k]+1, bIndex[k]+1
	}
	if ai == 0 && bi == 0 {
		for _, line := range a {
			edits = append(edits, Edit{OpDelete, line})
		}
		for _, line := range b {
			edits = append(edits, Edit{OpInsert, line})
		}
		return edits
	}
	return appendDiff(edits, a[ai:], b[bi:])
}

// LongestIncreasing returns the indices of a longest strictly
// increasing subsequence of values, in order.
func LongestIncreasing(values []int) []int {
	// tails[k] indexes the smallest value ending an increasing run of
	// length k+1; prev links each element to its predecessor in the
	// run it extends.
	var tails []int
	prev := make([]int, len(values))
	for i, v := range values {
		k := sort.Search(len(tails), func(k int) bool { return values[tails[k]] >= v })
		prev[i] = -1
		if k > 0 {
			prev[i] = tails[k-1]
		}
		if k == len(tails) {
			tails = append(tails, i)
		} else {
			tails[k] = i
		}
	}
	if len(tails) == 0 {
		return nil
	}
	out := make([]int, len(tails))
	for k, i := len(tails)-1, tails[len(tails)-1]; k >= 0; k-- {
		out[k] = i
		i = prev[i]
	}
	return out
}

// appendLCS appends a minimal edit script built from a longest-common-
// subsequence table. Deletes are emitted before inserts at each
// divergence point, matching conventional unified diff order.
func appendLCS(edits []Edit, a, b []string) []Edit {
	n, m := len(a), len(b)
	// lcs[i*(m+1)+j] is the LCS length of a[i:] and b[j:].
	stride := m + 1
	lcs := make([]int32, (n+1)*stride)
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i*stride+j] = lcs[(i+1)*stride+j+1] + 1
			} else {
				lcs[i*stride+j] = max(lcs[(i+1)*stride+j], lcs[i*stride+j+1])
			}
		}
	}

	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			edits = append(edits, Edit{OpEqual, a[i]})
			i, j = i+1, j+1
		case lcs[(i+1)*stride+j] >= lcs[i*stride+j+1]:
			edits = append(edits, Edit{OpDelete, a[i]})
			i++
		default:
			edits = append(edits, Edit{OpInsert, b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		edits = append(edits, Edit{OpDelete, a[i]})
	}
	for ; j < m; j++ {
		edits = append(edits, Edit{OpInsert, b[j]})
	}
	return edits
}
