// Package fndiff pairs the functions of two binaries and classifies
// how each pair differs, cheaply enough to handle very large binaries:
// only functions whose raw bytes differ are ever disassembled.
package fndiff

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/loov/ixdiff/internal/objfile"
)

// State classifies how a function differs between two binaries.
type State int

// The possible comparison states. StateUnknown is the invalid zero value.
const (
	StateUnknown State = iota
	StateIdentical
	StateChanged
	StateAdded
	StateRemoved
)

// String returns a short human-readable name of the state.
func (s State) String() string {
	switch s {
	case StateIdentical:
		return "identical"
	case StateChanged:
		return "changed"
	case StateAdded:
		return "added"
	case StateRemoved:
		return "removed"
	default:
		return "unknown"
	}
}

// Pair is one function compared across two binaries. Old is nil for
// added functions and New is nil for removed ones.
type Pair struct {
	Name string
	// RenamedFrom is the old binary's name for this function when the
	// pair was matched as a rename; empty otherwise.
	RenamedFrom string
	State       State
	Old         *objfile.Func
	New         *objfile.Func
}

// SizeDelta returns the change in function size in bytes.
func (p *Pair) SizeDelta() int64 {
	var old, new int64
	if p.Old != nil {
		old = int64(p.Old.Size)
	}
	if p.New != nil {
		new = int64(p.New.Size)
	}
	return new - old
}

// Compare pairs the functions of two binaries by name and triages each
// pair. Function bodies are compared bytewise; equal bodies are marked
// identical without any disassembly. The result is sorted by name.
func Compare(old, new *objfile.Binary) []*Pair {
	pairs := make([]*Pair, 0, len(new.Funcs))
	for name, nfn := range new.Funcs {
		p := &Pair{Name: name, New: nfn}
		if ofn, ok := old.Funcs[name]; ok {
			p.Old = ofn
			if bytes.Equal(ofn.Code(), nfn.Code()) {
				p.State = StateIdentical
			} else {
				p.State = StateChanged
			}
		} else {
			p.State = StateAdded
		}
		pairs = append(pairs, p)
	}
	for name, ofn := range old.Funcs {
		if _, ok := new.Funcs[name]; !ok {
			pairs = append(pairs, &Pair{Name: name, State: StateRemoved, Old: ofn})
		}
	}
	slices.SortFunc(pairs, func(a, b *Pair) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return pairs
}
