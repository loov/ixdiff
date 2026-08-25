package fndiff

import (
	"regexp"
	"strings"

	"github.com/loov/disasm/objfile"
)

// closureNum matches compiler-generated numbered suffixes whose
// numbers shift when unrelated closures are added or removed.
var closureNum = regexp.MustCompile(`\.(func|gowrap|deferwrap)\d+`)

// canonicalName strips the parts of a symbol name that the compiler
// renumbers or respecializes: closure numbering and generic type
// arguments. Two symbols with equal canonical names are candidate
// renames of each other.
func canonicalName(name string) string {
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	return closureNum.ReplaceAllString(name, ".$1")
}

// maxRenameCandidates bounds the body-similarity search; beyond this
// the quadratic candidate scan is skipped and only canonical-name
// matches are paired.
const maxRenameCandidates = 40000

// MatchRenames pairs added functions with removed ones that are
// likely renames and replaces the two single-sided pairs with one
// changed pair whose RenamedFrom records the old name.
//
// Two passes: added and removed functions whose canonical names match
// uniquely are paired first; the remaining candidates are paired when
// similar reports their bodies as near-identical. similar may be nil
// to skip the second pass.
func MatchRenames(pairs []*Pair, similar func(old, new *objfile.Func) bool) []*Pair {
	var added, removed []*Pair
	for _, p := range pairs {
		switch p.State {
		case StateAdded:
			added = append(added, p)
		case StateRemoved:
			removed = append(removed, p)
		}
	}
	if len(added) == 0 || len(removed) == 0 {
		return pairs
	}

	// uniqueByCanon maps a canonical name to its pair only when the
	// name is unambiguous on that side.
	uniqueByCanon := func(side []*Pair) map[string]*Pair {
		count := map[string]int{}
		for _, p := range side {
			count[canonicalName(p.Name)]++
		}
		unique := map[string]*Pair{}
		for _, p := range side {
			if c := canonicalName(p.Name); count[c] == 1 {
				unique[c] = p
			}
		}
		return unique
	}

	matched := map[*Pair]*Pair{} // removed -> added
	taken := map[*Pair]bool{}
	addedByCanon := uniqueByCanon(added)
	for canon, rem := range uniqueByCanon(removed) {
		if add, ok := addedByCanon[canon]; ok && canon != "" {
			matched[rem] = add
			taken[add] = true
		}
	}

	if similar != nil && len(added)*len(removed) <= maxRenameCandidates {
		for _, rem := range removed {
			if _, ok := matched[rem]; ok {
				continue
			}
			for _, add := range added {
				if !taken[add] {
					if similar(rem.Old, add.New) {
						matched[rem] = add
						taken[add] = true
						break
					}
				}
			}
		}
	}
	if len(matched) == 0 {
		return pairs
	}

	renamed := map[*Pair]*Pair{} // added -> merged replacement
	for rem, add := range matched {
		renamed[add] = &Pair{
			Name:        add.Name,
			RenamedFrom: rem.Name,
			State:       StateChanged,
			Old:         rem.Old,
			New:         add.New,
		}
	}
	out := make([]*Pair, 0, len(pairs)-len(matched))
	for _, p := range pairs {
		if _, ok := matched[p]; ok {
			continue // removed side is folded into the merged pair
		}
		if merged, ok := renamed[p]; ok {
			out = append(out, merged)
			continue
		}
		out = append(out, p)
	}
	return out
}
