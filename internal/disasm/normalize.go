package disasm

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/loov/ixdiff/internal/objfile"
)

// Lookup returns a SymLookup over the functions of bin, for resolving
// call targets to names during decoding.
func Lookup(bin *objfile.Binary) SymLookup {
	funcs := make([]*objfile.Func, 0, len(bin.Funcs))
	for _, fn := range bin.Funcs {
		funcs = append(funcs, fn)
	}
	// Ties broken by name so aliased symbols (e.g. f and f.abi0 at
	// the same address) resolve deterministically in both binaries.
	sort.Slice(funcs, func(i, j int) bool {
		if funcs[i].Addr != funcs[j].Addr {
			return funcs[i].Addr < funcs[j].Addr
		}
		return funcs[i].Name < funcs[j].Name
	})
	return func(addr uint64) (string, uint64) {
		i := sort.Search(len(funcs), func(i int) bool { return funcs[i].Addr > addr })
		if i > 0 && addr < funcs[i-1].Addr+funcs[i-1].Size {
			return funcs[i-1].Name, funcs[i-1].Addr
		}
		return "", 0
	}
}

// Normalize renders instructions as diff-ready lines by removing
// operands that change whenever code or data moves in the binary,
// while keeping everything an optimization could genuinely change:
//
//   - branch targets inside the function become stable L<index> labels
//   - absolute addresses that do not resolve to anything become <addr>
//   - IP-relative data displacements (amd64) become <data>(IP)
//   - ADRP page offsets (arm64) become <page>(PC), and the follow-up
//     low-12-bit immediates on ADRP'd registers become <lo12>
//
// Call targets are expected to be symbolized already, via a Lookup
// passed to Decode. Plain immediates are kept untouched.
func Normalize(name string, insts []Inst) []string {
	n := norm{name: name, indexAt: make(map[uint64]int, len(insts))}
	for i, in := range insts {
		n.indexAt[in.Addr] = i
	}
	if len(insts) > 0 {
		n.start = insts[0].Addr
	}

	// adrp holds registers whose value is an ADRP page address; the
	// low 12 bits of the target surface in the next instruction as a
	// plain immediate or displacement, which must be masked too.
	adrp := map[string]bool{}

	lines := make([]string, len(insts))
	for i, in := range insts {
		op, rest, hasArgs := strings.Cut(in.Text, " ")
		if !hasArgs {
			lines[i] = in.Text
			continue
		}
		args := strings.Split(rest, ", ")
		for j, arg := range args {
			args[j] = n.arg(in, arg, adrp)
		}
		dest := args[len(args)-1]
		if in.Op == "ADRP" {
			adrp[dest] = true
		} else {
			delete(adrp, dest)
		}
		lines[i] = op + " " + strings.Join(args, ", ")
	}
	return lines
}

// norm carries the per-function state used to normalize operands.
type norm struct {
	name    string
	start   uint64
	indexAt map[uint64]int
}

var (
	bareHex = regexp.MustCompile(`^0x[0-9a-f]+$`)
	pcRel   = regexp.MustCompile(`^(-?\d+)\(PC\)$`)
	ipDisp  = regexp.MustCompile(`^-?(0x[0-9a-f]+|\d+)\(IP\)$`)
	symRef  = regexp.MustCompile(`^(.+?)(\+\d+)?\(SB\)$`)
)

var (
	immArg  = regexp.MustCompile(`^\$\d+$`)
	dispArg = regexp.MustCompile(`^-?\d+\((R\d+|RSP)\)$`)
)

// arg rewrites a single operand according to the Normalize rules;
// operands it does not recognize pass through unchanged. adrp is the
// set of registers currently holding an ADRP page address.
func (n norm) arg(in Inst, arg string, adrp map[string]bool) string {
	if m := dispArg.FindStringSubmatch(arg); m != nil && adrp[m[1]] {
		return "<lo12>(" + m[1] + ")"
	}
	if in.Op == "ADD" && immArg.MatchString(arg) {
		// ADD $lo12, Rn, Rd completing an ADRP pair.
		if rest, ok := strings.CutPrefix(in.Text, "ADD "+arg+", "); ok {
			if reg, _, ok := strings.Cut(rest, ","); ok && adrp[reg] {
				return "$<lo12>"
			}
		}
	}
	switch {
	case bareHex.MatchString(arg):
		// amd64 branch target or unresolved absolute address.
		v, err := strconv.ParseUint(arg, 0, 64)
		if err == nil {
			if idx, ok := n.indexAt[v]; ok {
				return label(idx)
			}
		}
		return "<addr>"

	case pcRel.MatchString(arg):
		// arm64 pc-relative: instruction count for branches,
		// byte offset for ADRP page computation.
		if in.Op == "ADRP" {
			return "<page>(PC)"
		}
		d, err := strconv.ParseInt(pcRel.FindStringSubmatch(arg)[1], 10, 64)
		if err == nil {
			if idx, ok := n.indexAt[uint64(int64(in.Addr)+d*4)]; ok {
				return label(idx)
			}
		}
		return "<addr>(PC)"

	case ipDisp.MatchString(arg):
		// amd64 IP-relative data reference.
		return "<data>(IP)"

	default:
		// A reference to the function itself is a branch;
		// resolved targets render as name+decimal(SB).
		m := symRef.FindStringSubmatch(arg)
		if m == nil || m[1] != n.name {
			return arg
		}
		var off uint64
		if m[2] != "" {
			off, _ = strconv.ParseUint(m[2][1:], 10, 64)
		}
		if idx, ok := n.indexAt[n.start+off]; ok {
			return label(idx)
		}
		return arg
	}
}

// label formats a stable intra-function branch target.
func label(idx int) string {
	return "L" + strconv.Itoa(idx)
}
