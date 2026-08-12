package main

import (
	"encoding/json"
	"io"

	"github.com/loov/ixdiff/ixdiff"
)

// jsonSummary is the machine-readable form of the summary report.
type jsonSummary struct {
	Old        string                `json:"old"`
	New        string                `json:"new"`
	Arch       string                `json:"arch"`
	Counts     jsonCounts            `json:"counts"`
	SizeDelta  int64                 `json:"size_delta"`
	SpillDelta int                   `json:"spill_delta"`
	SlotDelta  int                   `json:"slot_delta"`
	OpDelta    ixdiff.OpCount        `json:"op_delta,omitempty"`
	Packages   []ixdiff.PackageDelta `json:"packages,omitempty"`
	Functions  []jsonFuncReport      `json:"functions"`
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
	SpillDelta     *int           `json:"spill_delta,omitempty"`
	SlotDelta      *int           `json:"slot_delta,omitempty"`
	RelocationOnly bool           `json:"relocation_only,omitempty"`
	OpDelta        ixdiff.OpCount `json:"op_delta,omitempty"`
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
var opNames = map[ixdiff.EditOp]string{
	ixdiff.Equal:  "equal",
	ixdiff.Delete: "delete",
	ixdiff.Insert: "insert",
}

// writeJSONSummary emits the summary report as one JSON object. With
// --all every ranked function carries its diff (changed) or full
// listing (added, removed).
func (c *cmdDiff) writeJSONSummary(w io.Writer, arch string, d *ixdiff.Diff, pairs []ixdiff.Pair) error {
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

	ranked := rankPairs(pairs, c.top, c.sortBy, c.stateSet)
	funcs := make([]jsonFuncReport, 0, len(ranked))
	for _, p := range ranked {
		var lines []ixdiff.Line
		if c.all {
			var err error
			if lines, err = d.Lines(p); err != nil {
				return err
			}
		}
		funcs = append(funcs, funcReport(p, lines, true, c.all))
	}

	return encodeJSON(w, jsonSummary{
		Old:  c.oldPath,
		New:  c.newPath,
		Arch: arch,
		Counts: jsonCounts{
			Identical:   counts[ixdiff.Identical],
			Changed:     counts[ixdiff.Changed],
			Relocations: counts[ixdiff.RelocationOnly],
			Added:       counts[ixdiff.Added],
			Removed:     counts[ixdiff.Removed],
		},
		SizeDelta:  sizeDelta,
		SpillDelta: spillDelta,
		SlotDelta:  slotDelta,
		OpDelta:    totalOps,
		Packages:   cappedPackages(pairs),
		Functions:  funcs,
	})
}

// writeJSONFuncs emits the --fn reports as one JSON array. A uniquely
// matched changed function includes its full diff; ambiguous matches
// are listed without one, mirroring the text output.
func (c *cmdDiff) writeJSONFuncs(w io.Writer, d *ixdiff.Diff, pairs []ixdiff.Pair) error {
	var reports []jsonFuncReport
	for _, name := range c.fns {
		matches, err := matchFuncs(pairs, name)
		if err != nil {
			return err
		}
		withDiff := len(matches) == 1
		for _, p := range matches {
			var lines []ixdiff.Line
			if withDiff {
				if lines, err = d.Lines(p); err != nil {
					return err
				}
			}
			// Changed functions always report their stats; added and
			// removed ones only when uniquely matched, matching the
			// text output that lists ambiguous matches without detail.
			withStats := withDiff || p.State == ixdiff.Changed
			reports = append(reports, funcReport(p, lines, withStats, withDiff))
		}
	}
	return encodeJSON(w, reports)
}

// funcReport converts one pair; withStats includes the instruction
// deltas and withDiff the edit script.
func funcReport(p ixdiff.Pair, lines []ixdiff.Line, withStats, withDiff bool) jsonFuncReport {
	r := jsonFuncReport{
		Name:        p.Name,
		RenamedFrom: p.RenamedFrom,
		State:       displayState(p.State),
		SizeDelta:   p.SizeDelta,
	}
	switch p.State {
	case ixdiff.Identical:
		return r
	case ixdiff.RelocationOnly:
		r.RelocationOnly = true
		return r
	}
	if withStats {
		r.InstDelta = &p.InstDelta
		r.SpillDelta = &p.SpillDelta
		r.SlotDelta = &p.SlotDelta
		r.OpDelta = p.OpDelta
	}
	if withDiff {
		for _, l := range lines {
			r.Diff = append(r.Diff, jsonDiffLine{
				Op:      opNames[l.Op],
				OldAddr: l.OldAddr,
				NewAddr: l.NewAddr,
				Text:    l.Text,
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
