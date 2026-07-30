package disasm

import (
	"regexp"
	"slices"
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

// Line is one normalized instruction. When the instruction branches
// inside the function, Target is the index of the target instruction
// and Text contains an internal marker where the label belongs; use
// Render to substitute the final label text.
type Line struct {
	Text   string
	Target int // target instruction index; -1 when not a branch
}

// targetMark is the placeholder inside Line.Text replaced by the
// label during Render. Assembly text never contains control bytes.
const targetMark = "\x01"

// Normalize renders instructions as diff-ready lines: NormalizeLines
// with labels numbered by target order.
func Normalize(name string, insts []Inst, opts Options) []string {
	lines := NormalizeLines(name, insts, opts)
	return Render(lines, TargetOrderLabels(lines))
}

// NormalizeLines rewrites instructions into diff-ready lines by
// removing operands that change whenever code or data moves in the
// binary, while keeping everything an optimization could genuinely
// change:
//
//   - branch targets inside the function become label slots, resolved
//     by Render
//   - absolute addresses that do not resolve to anything become <addr>
//   - IP-relative data displacements (amd64) become <data>(IP)
//   - ADRP page offsets (arm64) become <page>(PC), and the follow-up
//     low-12-bit immediates on ADRP'd registers become <lo12>
//
// Call targets are expected to be symbolized already, via a Lookup
// passed to Decode. Plain immediates are kept untouched.
func NormalizeLines(name string, insts []Inst, opts Options) []Line {
	n := norm{name: name, opts: opts, indexAt: make(map[uint64]int, len(insts))}
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

	lines := make([]Line, len(insts))
	for i, in := range insts {
		op, rest, hasArgs := strings.Cut(in.Text, " ")
		if !hasArgs {
			lines[i] = Line{Text: in.Text, Target: -1}
			continue
		}
		n.target = -1
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
		lines[i] = Line{Text: op + " " + strings.Join(args, ", "), Target: n.target}
	}
	return lines
}

// Render substitutes each line's label slot using labelOf, which maps
// a target instruction index to its label text.
func Render(lines []Line, labelOf func(int) string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		if l.Target >= 0 {
			out[i] = strings.Replace(l.Text, targetMark, labelOf(l.Target), 1)
		} else {
			out[i] = l.Text
		}
	}
	return out
}

// TargetOrderLabels numbers the distinct branch targets of lines as
// L1..Ln in instruction order. Numbering by target order rather than
// instruction index keeps labels stable when non-target instructions
// are inserted or removed.
func TargetOrderLabels(lines []Line) func(int) string {
	var targets []int
	seen := map[int]bool{}
	for _, l := range lines {
		if l.Target >= 0 && !seen[l.Target] {
			seen[l.Target] = true
			targets = append(targets, l.Target)
		}
	}
	slices.Sort(targets)
	number := make(map[int]int, len(targets))
	for i, t := range targets {
		number[t] = i + 1
	}
	return func(target int) string {
		return "L" + strconv.Itoa(number[target])
	}
}

// Options selects optional normalization rules.
type Options struct {
	// MaskSP masks stack-pointer displacements as <sp>(SP). A frame
	// size change shifts every stack offset in the function; masking
	// them keeps such a change to a single diff line at the cost of
	// hiding genuine spill-slot changes.
	MaskSP bool

	// IsAddr reports whether a value is an address inside the binary.
	// When set, hex immediates recognized as addresses are masked as
	// $<addr>: a constant like a loaded rodata pointer is relocation
	// noise, while small ordinary constants are left untouched.
	IsAddr func(uint64) bool
}

// norm carries the per-function state used to normalize operands.
type norm struct {
	name    string
	opts    Options
	start   uint64
	indexAt map[uint64]int
	// target is the branch target index of the instruction being
	// rewritten, -1 when it has none.
	target int
}

var (
	bareHex = regexp.MustCompile(`^0x[0-9a-f]+$`)
	pcRel   = regexp.MustCompile(`^(-?\d+)\(PC\)$`)
	ipDisp  = regexp.MustCompile(`^-?(0x[0-9a-f]+|\d+)\(IP\)$`)
	symRef  = regexp.MustCompile(`^(.+?)(\+\d+)?\(SB\)$`)
)

var (
	immArg  = regexp.MustCompile(`^\$\d+$`)
	immHex  = regexp.MustCompile(`^\$0x[0-9a-f]+$`)
	dispArg = regexp.MustCompile(`^-?\d+\((R\d+|RSP)\)$`)
	// spDisp matches stack displacements: hex on amd64 (0x10(SP)),
	// decimal on arm64 (-112(RSP)). A bare (SP) deref has no offset.
	spDisp = regexp.MustCompile(`^-?(?:0x[0-9a-f]+|\d+)\((SP|RSP)\)$`)
)

// arg rewrites a single operand according to the Normalize rules;
// operands it does not recognize pass through unchanged. adrp is the
// set of registers currently holding an ADRP page address.
func (n *norm) arg(in Inst, arg string, adrp map[string]bool) string {
	if n.opts.MaskSP {
		if m := spDisp.FindStringSubmatch(arg); m != nil {
			return "<sp>(" + m[1] + ")"
		}
	}
	if m := dispArg.FindStringSubmatch(arg); m != nil && adrp[m[1]] {
		return "<lo12>(" + m[1] + ")"
	}
	if n.opts.IsAddr != nil && immHex.MatchString(arg) {
		if v, err := strconv.ParseUint(arg[1:], 0, 64); err == nil && n.opts.IsAddr(v) {
			return "$<addr>"
		}
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
				return n.mark(idx)
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
				return n.mark(idx)
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
			return n.mark(idx)
		}
		return arg
	}
}

// mark records the branch target of the current instruction and
// returns the label placeholder.
func (n *norm) mark(idx int) string {
	n.target = idx
	return targetMark
}
