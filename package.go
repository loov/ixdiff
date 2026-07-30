package main

import (
	"cmp"
	"slices"
	"strings"

	"github.com/loov/ixdiff/internal/fndiff"
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

// pkgDelta aggregates the changes within one package.
type pkgDelta struct {
	Name      string `json:"name"`
	SizeDelta int64  `json:"size_delta"`
	InstDelta int    `json:"inst_delta"`
	Changed   int    `json:"changed"`
	Added     int    `json:"added"`
	Removed   int    `json:"removed"`
}

// pkgRollupCap bounds the package table; packages beyond it are rare
// stragglers with tiny deltas.
const pkgRollupCap = 20

// pkgRollup aggregates non-identical, non-relocation-only pairs by
// package, ordered by descending |size delta|.
func pkgRollup(pairs []*fndiff.Pair, analyzed []*analysis) []pkgDelta {
	noise := map[string]bool{}
	for _, a := range analyzed {
		if a.noise {
			noise[a.pair.Name] = true
		}
	}
	instDelta := instDeltas(analyzed)

	byPkg := map[string]*pkgDelta{}
	for _, p := range pairs {
		if p.State == fndiff.StateIdentical || noise[p.Name] {
			continue
		}
		pkg := pkgOf(p.Name)
		d := byPkg[pkg]
		if d == nil {
			d = &pkgDelta{Name: pkg}
			byPkg[pkg] = d
		}
		d.SizeDelta += p.SizeDelta()
		d.InstDelta += instDelta[p.Name]
		switch p.State {
		case fndiff.StateChanged:
			d.Changed++
		case fndiff.StateAdded:
			d.Added++
		case fndiff.StateRemoved:
			d.Removed++
		}
	}

	out := make([]pkgDelta, 0, len(byPkg))
	for _, d := range byPkg {
		out = append(out, *d)
	}
	slices.SortFunc(out, func(a, b pkgDelta) int {
		if d := abs64(b.SizeDelta) - abs64(a.SizeDelta); d != 0 {
			return int(d)
		}
		return cmp.Compare(a.Name, b.Name)
	})
	if len(out) > pkgRollupCap {
		out = out[:pkgRollupCap]
	}
	return out
}
