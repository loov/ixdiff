package main

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/loov/ixdiff/ixdiff"
)

// writeStats prints an overview of a single binary: its architecture,
// function count, text size, padding, opcode histogram, and the
// largest packages and functions.
func writeStats(w io.Writer, bin *ixdiff.Binary, top int) error {
	funcs := bin.Funcs()
	pad := bin.Padding()
	fmt.Fprintf(w, "arch: %s\n", bin.Arch())
	fmt.Fprintf(w, "functions: %d\n", len(funcs))
	fmt.Fprintf(w, "total text size: %d bytes (+%d alignment padding, +%d large gaps)\n",
		bin.TextBytes(), pad.Align, pad.Large)

	type pkgStat struct {
		name   string
		bytes  int64
		insts  int
		spills int
		slots  int
		funcs  int
	}
	pkgs := map[string]*pkgStat{}
	ops := ixdiff.OpCount{}
	var spills, slots int
	for _, f := range funcs {
		o, err := f.Ops()
		if err != nil {
			return fmt.Errorf("disassembling %s: %w", f.Name, err)
		}
		sp, _ := f.Spills()
		sl, _ := f.StackSlots()
		ops.Add(o)
		spills += sp
		slots += sl
		p := pkgs[f.Package]
		if p == nil {
			p = &pkgStat{name: f.Package}
			pkgs[f.Package] = p
		}
		p.bytes += f.Size
		p.insts += o.Total()
		p.spills += sp
		p.slots += sl
		p.funcs++
	}
	fmt.Fprintf(w, "total instructions: %d\n", ops.Total())
	fmt.Fprintf(w, "total spills: %d registers moved\n", spills)
	fmt.Fprintf(w, "total stack traffic: %d 8-byte slots\n", slots)

	if len(ops) > 0 {
		fmt.Fprintf(w, "\ninstructions by opcode:\n")
		for _, op := range sortedOps(ops) {
			fmt.Fprintf(w, "  %7d %s\n", ops[op], op)
		}
	}

	rollup := make([]*pkgStat, 0, len(pkgs))
	for _, p := range pkgs {
		rollup = append(rollup, p)
	}
	slices.SortFunc(rollup, func(a, b *pkgStat) int {
		return cmp.Or(cmp.Compare(b.bytes, a.bytes), cmp.Compare(a.name, b.name))
	})
	if len(rollup) > pkgRollupCap {
		rollup = rollup[:pkgRollupCap]
	}
	fmt.Fprintf(w, "\npackages by size:\n")
	fmt.Fprintf(w, "  %10s %8s %8s %8s %6s  %s\n", "bytes", "insts", "spills", "slots", "funcs", "package")
	for _, p := range rollup {
		fmt.Fprintf(w, "  %10d %8d %8d %8d %6d  %s\n", p.bytes, p.insts, p.spills, p.slots, p.funcs, p.name)
	}

	ranked := slices.Clone(funcs)
	slices.SortFunc(ranked, func(a, b *ixdiff.Func) int {
		return cmp.Or(cmp.Compare(b.Size, a.Size), cmp.Compare(a.Name, b.Name))
	})
	if len(ranked) > top {
		ranked = ranked[:top]
	}
	fmt.Fprintf(w, "\ntop %d functions by size:\n", len(ranked))
	for _, f := range ranked {
		fmt.Fprintf(w, "  %8d bytes  %s\n", f.Size, f.Name)
	}
	return nil
}

// writeFuncListings prints the disassembly of every function named by
// a --fn flag in a single binary, resolving names like matchFuncs.
func writeFuncListings(w io.Writer, bin *ixdiff.Binary, names []string) error {
	funcs := bin.Funcs()
	for i, name := range names {
		if i > 0 {
			fmt.Fprintln(w)
		}
		matches, err := matchNames(funcs, name)
		if err != nil {
			return err
		}
		if len(matches) > 1 {
			fmt.Fprintf(w, "%q matches %d functions:\n", name, len(matches))
			for _, f := range matches {
				fmt.Fprintf(w, "  %7d bytes  %s\n", f.Size, f.Name)
			}
			continue
		}
		f := matches[0]
		insts, err := f.Text()
		if err != nil {
			return fmt.Errorf("disassembling %s: %w", f.Name, err)
		}
		fmt.Fprintf(w, "%s (%d bytes, %d instructions)\n", f.Name, f.Size, len(insts))
		for _, in := range insts {
			fmt.Fprintf(w, "  %#x  %s\n", in.Addr, in.Text)
		}
	}
	return nil
}

// matchNames is matchFuncs over the functions of one binary.
func matchNames(funcs []*ixdiff.Func, name string) ([]*ixdiff.Func, error) {
	var matches []*ixdiff.Func
	for _, f := range funcs {
		if f.Name == name {
			return []*ixdiff.Func{f}, nil
		}
		if strings.Contains(f.Name, name) {
			matches = append(matches, f)
		}
	}
	if len(matches) == 0 {
		pairs := make([]ixdiff.Pair, len(funcs))
		for i, f := range funcs {
			pairs[i].Name = f.Name
		}
		if close := closestNames(pairs, name, 3); len(close) > 0 {
			return nil, fmt.Errorf("function %q not found, did you mean: %s", name, strings.Join(close, ", "))
		}
		return nil, fmt.Errorf("function %q not found", name)
	}
	return matches, nil
}
