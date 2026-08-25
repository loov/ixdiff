package ixdiff

import (
	"fmt"
	"runtime"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/loov/disasm/objfile"
	"github.com/loov/ixdiff/internal/fndiff"
	"github.com/loov/ixdiff/internal/norm"
)

// State classifies how a function differs between two binaries.
type State int

// The possible comparison states. The zero value is invalid.
const (
	// Identical means the function bytes are equal in both binaries.
	Identical State = iota + 1
	// RelocationOnly means the bytes differ, but only in relocated
	// addresses: the normalized assembly is identical.
	RelocationOnly
	// Changed means the generated code differs.
	Changed
	// Added means the function exists only in the new binary.
	Added
	// Removed means the function exists only in the old binary.
	Removed
)

// String returns a short human-readable name of the state.
func (s State) String() string {
	switch s {
	case Identical:
		return "identical"
	case RelocationOnly:
		return "relocation-only"
	case Changed:
		return "changed"
	case Added:
		return "added"
	case Removed:
		return "removed"
	default:
		return "unknown"
	}
}

// EditOp is the kind of a diff line.
type EditOp int

// The edit kinds. Equal keeps a line, Delete removes a line from the
// old side, Insert adds a line on the new side.
const (
	Equal EditOp = iota
	Delete
	Insert
)

// Line is one line of a function diff: an edit with the addresses of
// the instructions it came from, so every line can be cross-referenced
// with objdump or a profiler. OldAddr is zero for inserts and NewAddr
// is zero for deletes.
type Line struct {
	Op               EditOp
	OldAddr, NewAddr uint64
	Text             string
}

// Pair is one function compared across two binaries.
type Pair struct {
	Name string
	// RenamedFrom is the old binary's name for this function when the
	// pair was matched as a rename; empty otherwise.
	RenamedFrom string
	// Old and New are the two sides; Old is nil for added functions
	// and New is nil for removed ones.
	Old, New *Func
	State    State
	// SizeDelta is the change in function size in bytes.
	SizeDelta int64
	// InstDelta is the change in instruction count; zero for identical
	// and relocation-only pairs.
	InstDelta int
	// OpDelta is the per-mnemonic instruction count change; nil for
	// identical and relocation-only pairs.
	OpDelta OpCount
	// SpillDelta is the change in the number of registers moved to or
	// from the stack — spills and reloads, but also stack-passed call
	// arguments and register saves; zero for identical and
	// relocation-only pairs. See [Func.Spills].
	SpillDelta int
	// SlotDelta is the change in the number of 8-byte stack slots
	// touched by those accesses. Unlike SpillDelta it is neutral under
	// pair/vector/scalar lowering conversions: it tracks memory
	// traffic, not register-pressure events. Zero for identical and
	// relocation-only pairs. See [Func.StackSlots].
	SlotDelta int
}

// Options selects optional comparison behavior. The zero value is the
// default comparison.
type Options struct {
	// MaskSP masks stack-pointer displacements. A frame size change
	// shifts every stack offset in a function; masking keeps such a
	// change to a single diff line at the cost of hiding genuine
	// spill-slot changes.
	MaskSP bool
}

// Diff is the result of comparing two binaries.
type Diff struct {
	old, new *Binary
	norm     norm.Options
	pairs    []Pair
	// lines holds the eagerly computed edit scripts of changed pairs,
	// keyed by pair name.
	lines map[string][]Line
}

// Compare pairs the functions of two binaries and analyzes every
// non-identical pair: renamed functions are matched by body
// similarity, byte differences that are pure relocation noise are
// classified RelocationOnly, and changed pairs get a normalized
// instruction-level edit script. It errors when the binaries target
// different architectures or code fails to decode. A nil opts selects
// the defaults.
func Compare(old, new *Binary, opts *Options) (*Diff, error) {
	if opts == nil {
		opts = &Options{}
	}
	if old.obj.Arch != new.obj.Arch {
		return nil, fmt.Errorf("architecture mismatch: %v vs %v", old.obj.Arch, new.obj.Arch)
	}
	norm := norm.Options{MaskSP: opts.MaskSP, Arch: old.obj.Arch}

	fpairs := fndiff.Compare(old.obj, new.obj)
	fpairs = fndiff.MatchRenames(fpairs, bodySimilar(old, new, norm))

	var nonIdentical []*fndiff.Pair
	for _, p := range fpairs {
		if p.State != fndiff.StateIdentical {
			nonIdentical = append(nonIdentical, p)
		}
	}
	analyzed, err := analyze(nonIdentical, old, new, runtime.NumCPU(), norm)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]*analysis, len(analyzed))
	for _, a := range analyzed {
		byName[a.pair.Name] = a
	}

	d := &Diff{old: old, new: new, norm: norm, lines: map[string][]Line{}}
	for _, fp := range fpairs {
		p := Pair{
			Name:        fp.Name,
			RenamedFrom: fp.RenamedFrom,
			SizeDelta:   fp.SizeDelta(),
		}
		if fp.Old != nil {
			oldName := fp.Name
			if fp.RenamedFrom != "" {
				oldName = fp.RenamedFrom
			}
			p.Old, _ = old.Func(oldName)
		}
		if fp.New != nil {
			p.New, _ = new.Func(fp.Name)
		}
		switch fp.State {
		case fndiff.StateIdentical:
			p.State = Identical
		case fndiff.StateChanged:
			p.State = Changed
		case fndiff.StateAdded:
			p.State = Added
		case fndiff.StateRemoved:
			p.State = Removed
		}
		if a := byName[fp.Name]; a != nil {
			if a.noise {
				p.State = RelocationOnly
			} else {
				p.InstDelta = a.instDelta
				p.OpDelta = a.opDelta
				p.SpillDelta = a.spillDelta
				p.SlotDelta = a.slotDelta
				if fp.State == fndiff.StateChanged {
					d.lines[fp.Name] = toLines(fndiff.ResolveLines(a.edits, a.oldAddrs, a.newAddrs))
				}
			}
		}
		d.pairs = append(d.pairs, p)
	}
	return d, nil
}

// Pairs returns every compared pair — identical, relocation-only,
// changed, added, and removed — in name order. The returned slice is
// shared and must not be modified.
func (d *Diff) Pairs() []Pair { return d.pairs }

// SizeDelta returns the total function size change in bytes.
func (d *Diff) SizeDelta() int64 {
	var total int64
	for _, p := range d.pairs {
		total += p.SizeDelta
	}
	return total
}

// OpDelta returns the aggregated per-mnemonic instruction count
// change. Relocation-only pairs are excluded and entries that cancel
// out are removed.
func (d *Diff) OpDelta() OpCount {
	total := OpCount{}
	for _, p := range d.pairs {
		if p.State != RelocationOnly {
			total.Add(p.OpDelta)
		}
	}
	total.Compact()
	return total
}

// Packages returns the changes aggregated by package, ordered by
// descending |size delta|.
func (d *Diff) Packages() []PackageDelta { return PackageDeltas(d.pairs) }

// Lines returns the edit script of a pair: the retained analysis for
// changed pairs, a full all-insert or all-delete listing for added and
// removed ones (decoded on demand, hence the error), and nil for
// identical and relocation-only pairs.
func (d *Diff) Lines(p Pair) ([]Line, error) {
	switch p.State {
	case Changed:
		return d.lines[p.Name], nil
	case Added, Removed:
		return d.listing(p)
	}
	return nil, nil
}

// listing builds an all-insert (added) or all-delete (removed) edit
// script so single-sided functions can render as a full assembly
// listing.
func (d *Diff) listing(p Pair) ([]Line, error) {
	fn, bin, op := p.New, d.new, fndiff.OpInsert
	if p.State == Removed {
		fn, bin, op = p.Old, d.old, fndiff.OpDelete
	}
	insts, err := bin.obj.Disassemble(fn.obj)
	if err != nil {
		return nil, fmt.Errorf("disassembling %s: %w", p.Name, err)
	}
	opts := d.norm
	opts.IsAddr = bin.obj.Contains
	opts.DataSym = bin.obj.DataSym
	normalized := norm.Normalize(fn.Name, insts, opts)
	edits := make([]fndiff.Edit, len(normalized))
	for i, text := range normalized {
		edits[i] = fndiff.Edit{Op: op, Text: text}
	}
	addrs := norm.Addrs(insts)
	if op == fndiff.OpInsert {
		return toLines(fndiff.ResolveLines(edits, nil, addrs)), nil
	}
	return toLines(fndiff.ResolveLines(edits, addrs, nil)), nil
}

// toLines converts resolved fndiff edits into the exported Line form.
func toLines(resolved []fndiff.Line) []Line {
	out := make([]Line, len(resolved))
	for i, l := range resolved {
		out[i] = Line{Op: EditOp(l.Op), OldAddr: l.OldAddr, NewAddr: l.NewAddr, Text: l.Text}
	}
	return out
}

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
	opDelta OpCount
	// spillDelta is the change in registers moved to or from the
	// stack; slotDelta the change in 8-byte stack slots touched.
	spillDelta, slotDelta int
	// noise reports that the normalized instructions are equal:
	// the byte difference was pure relocation noise.
	noise bool
}

// analyze disassembles every non-identical pair, limited to limit-way
// concurrency. Changed pairs are additionally diffed; added and
// removed functions contribute only their instruction counts. The
// result keeps the input order.
func analyze(pairs []*fndiff.Pair, old, new *Binary, limit int, opts norm.Options) ([]*analysis, error) {
	oldObj, newObj := old.obj, new.obj

	results := make([]*analysis, len(pairs))
	var g errgroup.Group
	g.SetLimit(limit)
	for i, p := range pairs {
		g.Go(func() error {
			if p.State == fndiff.StateChanged &&
				norm.RelocOnly(oldObj.Arch, p.Old.Code(), p.New.Code(),
					p.Old.Addr, p.New.Addr, oldObj.Lookup, newObj.Lookup, oldObj.DataSym, newObj.DataSym) {
				// Provably relocation-only: skip disassembly.
				results[i] = &analysis{pair: p, noise: true}
				return nil
			}

			var oldInsts, newInsts []norm.Inst
			var err error
			if p.Old != nil {
				oldInsts, err = oldObj.Disassemble(p.Old)
				if err != nil {
					return fmt.Errorf("disassembling old %s: %w", p.Name, err)
				}
			}
			if p.New != nil {
				newInsts, err = newObj.Disassemble(p.New)
				if err != nil {
					return fmt.Errorf("disassembling new %s: %w", p.Name, err)
				}
			}

			oldSpills, oldSlots := countSpills(oldObj.Arch, oldInsts)
			newSpills, newSlots := countSpills(oldObj.Arch, newInsts)
			a := &analysis{
				pair:       p,
				instDelta:  countInsts(newInsts) - countInsts(oldInsts),
				opDelta:    countOps(ops(oldInsts)).Delta(countOps(ops(newInsts))),
				spillDelta: newSpills - oldSpills,
				slotDelta:  newSlots - oldSlots,
			}
			if p.State == fndiff.StateChanged {
				oldOpts, newOpts := opts, opts
				oldOpts.IsAddr, newOpts.IsAddr = oldObj.Contains, newObj.Contains
				oldOpts.DataSym, newOpts.DataSym = oldObj.DataSym, newObj.DataSym
				oldLines, newLines := fndiff.AlignLabels(
					norm.NormalizeLines(p.Old.Name, oldInsts, oldOpts),
					norm.NormalizeLines(p.New.Name, newInsts, newOpts))
				a.edits = fndiff.Diff(oldLines, newLines)
				a.noise = slices.Equal(oldLines, newLines)
				a.oldAddrs = norm.Addrs(oldInsts)
				a.newAddrs = norm.Addrs(newInsts)
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
func bodySimilar(old, new *Binary, opts norm.Options) func(oldF, newF *objfile.Func) bool {
	oldObj, newObj := old.obj, new.obj
	return func(oldF, newF *objfile.Func) bool {
		small, large := oldF.Size, newF.Size
		if small > large {
			small, large = large, small
		}
		if small*5 < large*4 || pkgOf(oldF.Name) != pkgOf(newF.Name) {
			return false
		}

		oldInsts, err := oldObj.Disassemble(oldF)
		if err != nil {
			return false
		}
		newInsts, err := newObj.Disassemble(newF)
		if err != nil {
			return false
		}
		oldOpts, newOpts := opts, opts
		oldOpts.IsAddr, newOpts.IsAddr = oldObj.Contains, newObj.Contains
		oldOpts.DataSym, newOpts.DataSym = oldObj.DataSym, newObj.DataSym
		// Each side normalizes under its own symbol name so
		// self-referencing branches become labels on both sides and a
		// pure rename compares equal.
		oldLines := norm.Normalize(oldF.Name, oldInsts, oldOpts)
		newLines := norm.Normalize(newF.Name, newInsts, newOpts)

		equal := 0
		for _, e := range fndiff.Diff(oldLines, newLines) {
			if e.Op == fndiff.OpEqual {
				equal++
			}
		}
		return equal*10 >= max(len(oldLines), len(newLines))*9
	}
}
