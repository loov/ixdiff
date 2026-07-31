package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/fndiff"
	"github.com/loov/ixdiff/internal/objfile"
)

// A block is a run of instructions entered only at its first line: it
// starts at a branch target or after an unconditional control
// transfer.
type block struct {
	lines []string
	addrs []uint64
}

// content returns the block's comparison key.
func (b block) content() string { return strings.Join(b.lines, "\n") }

// unconditional lists the mnemonics after which control never falls
// through, ending a block.
var unconditional = map[string]bool{
	"JMP": true, "RET": true, "UD2": true, "INT": true,
	"B": true, "BR": true, "UDF": true,
}

// splitBlocks cuts rendered lines into basic blocks. leaders marks
// instruction indices that start a block (branch targets) and ends
// marks instructions after which a block ends (any branch or
// unconditional transfer).
func splitBlocks(lines []string, addrs []uint64, leaders, ends map[int]bool) []block {
	var blocks []block
	var cur block
	flush := func() {
		if len(cur.lines) > 0 {
			blocks = append(blocks, cur)
			cur = block{}
		}
	}
	for i, line := range lines {
		if leaders[i] {
			flush()
		}
		cur.lines = append(cur.lines, line)
		cur.addrs = append(cur.addrs, addrs[i])
		if ends[i] {
			flush()
		}
	}
	flush()
	return blocks
}

// blockEnds marks every instruction that terminates a basic block: an
// intra-function branch (it has a label target), or an unconditional
// transfer.
func blockEnds(nl []disasm.Line, insts []disasm.Inst) map[int]bool {
	ends := map[int]bool{}
	for i, l := range nl {
		if l.Target >= 0 || unconditional[insts[i].Op] {
			ends[i] = true
		}
	}
	return ends
}

// blockMove describes an identical block found at a different position.
type blockMove struct {
	oldAddr, newAddr uint64
	insts            int
}

// matchBlocks pairs identical blocks across the two sides in order.
// It returns notes for blocks that moved, and the concatenated
// leftovers of each side for a conventional diff.
func matchBlocks(old, new []block) (moves []blockMove, restOld, restNew block) {
	byContent := map[string][]int{}
	for i, b := range old {
		key := b.content()
		byContent[key] = append(byContent[key], i)
	}
	matched := make([]int, len(new)) // new index -> old index, -1 unmatched
	usedOld := make([]bool, len(old))
	for i, b := range new {
		matched[i] = -1
		key := b.content()
		for _, oi := range byContent[key] {
			if !usedOld[oi] {
				usedOld[oi] = true
				matched[i] = oi
				break
			}
		}
	}

	// A matched pair is "moved" when its old index breaks the
	// ascending order established by the pairs before it.
	lastOld := -1
	for i, oi := range matched {
		if oi < 0 {
			restNew.lines = append(restNew.lines, new[i].lines...)
			restNew.addrs = append(restNew.addrs, new[i].addrs...)
			continue
		}
		if oi < lastOld {
			moves = append(moves, blockMove{
				oldAddr: old[oi].addrs[0],
				newAddr: new[i].addrs[0],
				insts:   len(new[i].lines),
			})
			continue
		}
		lastOld = oi
	}
	for i, b := range old {
		if !usedOld[i] {
			restOld.lines = append(restOld.lines, b.lines...)
			restOld.addrs = append(restOld.addrs, b.addrs...)
		}
	}
	return moves, restOld, restNew
}

// writeFuncBlocks prints a block-matched diff of one changed function:
// identical blocks that only moved become one-line notes, and only the
// genuinely unmatched instructions are diffed. Useful when the
// compiler reordered basic blocks (e.g. PGO), where a linear diff
// drowns in relocation of unchanged code.
//
// ponytail: a block that both moved and changed shows as delete plus
// insert; fuzzy block matching would pair those, add it if PGO
// comparisons need it. Measured on a real PGO pair (ixdiff built with
// and without a profile of itself, 2026-07): moved-and-changed blocks
// reduced diff lines by under 1% in 3 of 34 changed functions, so
// fuzzy matching stays unimplemented.
func writeFuncBlocks(w io.Writer, p *fndiff.Pair, old, new *objfile.Binary, opts disasm.Options, pal palette) error {
	oldInsts, err := disasm.Decode(old.Arch, p.Old.Code(), p.Old.Addr, disasm.Lookup(old))
	if err != nil {
		return fmt.Errorf("disassembling old %s: %w", p.Name, err)
	}
	newInsts, err := disasm.Decode(new.Arch, p.New.Code(), p.New.Addr, disasm.Lookup(new))
	if err != nil {
		return fmt.Errorf("disassembling new %s: %w", p.Name, err)
	}
	oldOpts, newOpts := opts, opts
	oldOpts.IsAddr, newOpts.IsAddr = old.Contains, new.Contains
	oldOpts.DataSym, newOpts.DataSym = old.DataSym, new.DataSym
	oldNL := disasm.NormalizeLines(p.Old.Name, oldInsts, oldOpts)
	newNL := disasm.NormalizeLines(p.New.Name, newInsts, newOpts)
	oldLines, newLines := alignLabels(oldNL, newNL)

	oldBlocks := splitBlocks(oldLines, addrs(oldInsts), targetSet(oldNL), blockEnds(oldNL, oldInsts))
	newBlocks := splitBlocks(newLines, addrs(newInsts), targetSet(newNL), blockEnds(newNL, newInsts))
	moves, restOld, restNew := matchBlocks(oldBlocks, newBlocks)

	writeDiffHeader(w, p)
	for _, m := range moves {
		fmt.Fprintf(w, "block of %d unchanged insts moved: %x -> %x\n", m.insts, m.oldAddr, m.newAddr)
	}
	if len(restOld.lines) == 0 && len(restNew.lines) == 0 {
		if len(moves) == 0 {
			fmt.Fprintf(w, "all blocks match\n")
		}
		return nil
	}
	rest := &analysis{
		pair:     p,
		edits:    fndiff.Diff(restOld.lines, restNew.lines),
		oldAddrs: restOld.addrs,
		newAddrs: restNew.addrs,
	}
	writeHunks(w, rest, pal)
	return nil
}

// targetSet collects the branch-target instruction indices of lines.
func targetSet(lines []disasm.Line) map[int]bool {
	targets := map[int]bool{0: true}
	for _, l := range lines {
		if l.Target >= 0 {
			targets[l.Target] = true
		}
	}
	return targets
}
