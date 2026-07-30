package fndiff

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

// Diff computes a minimal line diff from a to b. Equal inputs produce
// all-OpEqual output.
//
// ponytail: longest-common-subsequence DP, O(len(a)*len(b)) time and
// space after trimming the common prefix and suffix. Functions are at
// most a few thousand instructions and mostly unchanged, so the
// trimmed region stays small; switch to Myers if profiling disagrees.
func Diff(a, b []string) []Edit {
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

	edits := make([]Edit, 0, len(a)+len(b)-prefix-suffix)
	for _, line := range a[:prefix] {
		edits = append(edits, Edit{OpEqual, line})
	}
	edits = append(edits, lcsDiff(a[prefix:len(a)-suffix], b[prefix:len(b)-suffix])...)
	for _, line := range a[len(a)-suffix:] {
		edits = append(edits, Edit{OpEqual, line})
	}
	return edits
}

// lcsDiff produces a minimal edit script via a longest-common-
// subsequence table. Deletes are emitted before inserts at each
// divergence point, matching conventional unified diff order.
func lcsDiff(a, b []string) []Edit {
	n, m := len(a), len(b)
	// lcs[i][j] is the LCS length of a[i:] and b[j:].
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}

	edits := make([]Edit, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			edits = append(edits, Edit{OpEqual, a[i]})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
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
