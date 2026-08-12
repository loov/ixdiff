package ixdiff

import (
	"cmp"
	"slices"
	"strings"
)

// pkgOf extracts the package part of a Go symbol name: everything up
// to the first dot after the last slash, with generic type arguments
// stripped first. Runtime-generated symbols like type:.eq.x group
// under their prefix.
func pkgOf(name string) string {
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	start := strings.LastIndexByte(name, '/') + 1
	if i := strings.IndexByte(name[start:], '.'); i >= 0 {
		return name[:start+i]
	}
	return name
}

// PackageDelta aggregates the changes within one package.
type PackageDelta struct {
	Name       string `json:"name"`
	SizeDelta  int64  `json:"size_delta"`
	InstDelta  int    `json:"inst_delta"`
	SpillDelta int    `json:"spill_delta"`
	SlotDelta  int    `json:"slot_delta"`
	Changed    int    `json:"changed"`
	Added      int    `json:"added"`
	Removed    int    `json:"removed"`
}

// PackageDeltas aggregates pairs by package, ordered by descending
// |size delta|, then name. Identical and relocation-only pairs are
// excluded: they carry no code change.
func PackageDeltas(pairs []Pair) []PackageDelta {
	byPkg := map[string]*PackageDelta{}
	for _, p := range pairs {
		if p.State == Identical || p.State == RelocationOnly {
			continue
		}
		pkg := pkgOf(p.Name)
		d := byPkg[pkg]
		if d == nil {
			d = &PackageDelta{Name: pkg}
			byPkg[pkg] = d
		}
		d.SizeDelta += p.SizeDelta
		d.InstDelta += p.InstDelta
		d.SpillDelta += p.SpillDelta
		d.SlotDelta += p.SlotDelta
		switch p.State {
		case Changed:
			d.Changed++
		case Added:
			d.Added++
		case Removed:
			d.Removed++
		}
	}

	out := make([]PackageDelta, 0, len(byPkg))
	for _, d := range byPkg {
		out = append(out, *d)
	}
	slices.SortFunc(out, func(a, b PackageDelta) int {
		if d := abs64(b.SizeDelta) - abs64(a.SizeDelta); d != 0 {
			return int(d)
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return out
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
