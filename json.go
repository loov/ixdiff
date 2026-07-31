package main

import (
	"encoding/json"
	"io"

	"github.com/loov/ixdiff/internal/fndiff"
	"github.com/loov/ixdiff/internal/objfile"
)

// jsonSummary is the machine-readable form of the summary report.
type jsonSummary struct {
	Old       string           `json:"old"`
	New       string           `json:"new"`
	Arch      string           `json:"arch"`
	Counts    jsonCounts       `json:"counts"`
	SizeDelta int64            `json:"size_delta"`
	OpDelta   fndiff.OpCount   `json:"op_delta,omitempty"`
	Packages  []pkgDelta       `json:"packages,omitempty"`
	Functions []jsonFuncReport `json:"functions"`
}

// jsonCounts is the pair classification breakdown. Relocations counts
// functions whose bytes differ only by relocation; they are not
// included in Changed.
type jsonCounts struct {
	Identical   int `json:"identical"`
	Changed     int `json:"changed"`
	Relocations int `json:"relocations"`
	Added       int `json:"added"`
	Removed     int `json:"removed"`
}

// jsonFuncReport describes one function in either the ranked summary
// list or a --fn report. Diff is present only for --fn on a changed
// function.
type jsonFuncReport struct {
	Name           string         `json:"name"`
	RenamedFrom    string         `json:"renamed_from,omitempty"`
	State          string         `json:"state"`
	SizeDelta      int64          `json:"size_delta"`
	InstDelta      *int           `json:"inst_delta,omitempty"`
	RelocationOnly bool           `json:"relocation_only,omitempty"`
	OpDelta        fndiff.OpCount `json:"op_delta,omitempty"`
	Diff           []jsonDiffLine `json:"diff,omitempty"`
}

// jsonDiffLine is one line of a function diff.
type jsonDiffLine struct {
	Op      string `json:"op"` // "equal", "delete", or "insert"
	OldAddr uint64 `json:"old_addr,omitempty"`
	NewAddr uint64 `json:"new_addr,omitempty"`
	Text    string `json:"text"`
}

// opNames maps edit kinds to their JSON names.
var opNames = map[fndiff.Op]string{
	fndiff.OpEqual:  "equal",
	fndiff.OpDelete: "delete",
	fndiff.OpInsert: "insert",
}

// writeJSONSummary emits the summary report as one JSON object. With
// --all every ranked function carries its diff (changed) or full
// listing (added, removed).
func (c *cmdDiff) writeJSONSummary(w io.Writer, arch string, pairs []*fndiff.Pair, analyzed []*analysis, old, new *objfile.Binary) error {
	byName := map[string]*analysis{}
	noise := 0
	totalOps := fndiff.OpCount{}
	for _, a := range analyzed {
		byName[a.pair.Name] = a
		if a.noise {
			noise++
			continue
		}
		totalOps.Add(a.opDelta)
	}
	totalOps.Compact()
	counts := map[fndiff.State]int{}
	var sizeDelta int64
	for _, p := range pairs {
		counts[p.State]++
		sizeDelta += p.SizeDelta()
	}

	instDelta := instDeltas(analyzed)
	ranked := rankPairs(pairs, instDelta, c.top, c.sortBy)
	funcs := make([]jsonFuncReport, 0, len(ranked))
	for _, p := range ranked {
		a := byName[p.Name]
		if c.all && (p.State == fndiff.StateAdded || p.State == fndiff.StateRemoved) {
			var err error
			if a, err = listing(p, old, new, c.norm()); err != nil {
				return err
			}
		}
		funcs = append(funcs, funcReport(p, a, c.all))
	}

	return encodeJSON(w, jsonSummary{
		Old:  c.oldPath,
		New:  c.newPath,
		Arch: arch,
		Counts: jsonCounts{
			Identical:   counts[fndiff.StateIdentical],
			Changed:     counts[fndiff.StateChanged] - noise,
			Relocations: noise,
			Added:       counts[fndiff.StateAdded],
			Removed:     counts[fndiff.StateRemoved],
		},
		SizeDelta: sizeDelta,
		OpDelta:   totalOps,
		Packages:  pkgRollup(pairs, analyzed),
		Functions: funcs,
	})
}

// funcReport converts one analyzed pair; withDiff includes the edit
// script for changed functions.
func funcReport(p *fndiff.Pair, a *analysis, withDiff bool) jsonFuncReport {
	r := jsonFuncReport{
		Name:        p.Name,
		RenamedFrom: p.RenamedFrom,
		State:       p.State.String(),
		SizeDelta:   p.SizeDelta(),
	}
	if a == nil {
		return r
	}
	r.RelocationOnly = a.noise
	if !a.noise {
		r.InstDelta = &a.instDelta
		r.OpDelta = a.opDelta
	}
	if withDiff && !a.noise {
		for _, l := range diffLines(a) {
			r.Diff = append(r.Diff, jsonDiffLine{
				Op:      opNames[l.op],
				OldAddr: l.oldAddr,
				NewAddr: l.newAddr,
				Text:    l.text,
			})
		}
	}
	return r
}

// encodeJSON writes v indented, with a trailing newline.
func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
