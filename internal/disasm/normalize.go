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
//   - pc-relative data references (s390x larl etc.) become <addr>(PC)
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

	// adrp maps registers holding an ADRP page address to that page,
	// so follow-up low-12-bit immediates can be resolved to symbols.
	adrp := map[string]uint64{}

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
			if page, ok := adrpPage(in); ok {
				adrp[dest] = page
			} else {
				delete(adrp, dest)
			}
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

	// DataSym resolves an address to the name, base address, and size
	// of the data symbol containing it. When set, data references
	// render as sym+off instead of being masked, so a load that
	// switched to a different global is visible in the diff.
	DataSym DataLookup
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
	immArg = regexp.MustCompile(`^\$\d+$`)
	immHex = regexp.MustCompile(`^\$0x[0-9a-f]+$`)
	// A zero displacement renders as a bare (Rn), so the offset part
	// is optional: masking must treat 0(Rn) and (Rn) alike or an
	// offset shifting to or from zero leaks through.
	dispArg = regexp.MustCompile(`^(-?\d+)?\((R\d+|RSP)\)$`)
	// spDisp matches stack displacements: hex on amd64 (0x10(SP)),
	// decimal on arm64 (-112(RSP)).
	spDisp = regexp.MustCompile(`^(?:-?(?:0x[0-9a-f]+|\d+))?\((SP|RSP)\)$`)
)

// arg rewrites a single operand according to the Normalize rules;
// operands it does not recognize pass through unchanged. adrp maps
// registers currently holding an ADRP page address to that page.
func (n *norm) arg(in Inst, arg string, adrp map[string]uint64) string {
	if n.opts.MaskSP {
		if m := spDisp.FindStringSubmatch(arg); m != nil {
			return "<sp>(" + m[1] + ")"
		}
	}
	if m := dispArg.FindStringSubmatch(arg); m != nil {
		if page, ok := adrp[m[2]]; ok {
			var off int64
			if m[1] != "" {
				off, _ = strconv.ParseInt(m[1], 10, 64)
			}
			if ref, ok := n.data(page + uint64(off)); ok {
				return ref + "(" + m[2] + ")"
			}
			return "<lo12>(" + m[2] + ")"
		}
	}
	if n.opts.IsAddr != nil && immHex.MatchString(arg) {
		if v, err := strconv.ParseUint(arg[1:], 0, 64); err == nil && n.opts.IsAddr(v) {
			return "$<addr>"
		}
	}
	if in.Op == "ADD" && immArg.MatchString(arg) {
		// ADD $lo12, Rn, Rd completing an ADRP pair.
		if rest, ok := strings.CutPrefix(in.Text, "ADD "+arg+", "); ok {
			if reg, _, ok := strings.Cut(rest, ","); ok {
				if page, tracked := adrp[reg]; tracked {
					imm, _ := strconv.ParseUint(arg[1:], 10, 64)
					if ref, ok := n.data(page + imm); ok {
						return "$" + ref
					}
					return "$<lo12>"
				}
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
		// pc-relative, in units of the instruction's own length:
		// always 4 on arm64, 2/4/6 on s390x. Branches inside the
		// function become labels; anything else — including s390x
		// relative data references (LARL and friends), whose exact
		// byte offset the off(PC) rendering truncates away — is
		// masked as relocation noise. ADRP is a byte offset instead,
		// handled by the page computation.
		if in.Op == "ADRP" {
			return "<page>(PC)"
		}
		d, err := strconv.ParseInt(pcRel.FindStringSubmatch(arg)[1], 10, 64)
		if err == nil {
			if idx, ok := n.indexAt[uint64(int64(in.Addr)+d*int64(in.Len))]; ok {
				return n.mark(idx)
			}
		}
		return "<addr>(PC)"

	case ipDisp.MatchString(arg):
		// amd64 IP-relative data reference; the target is relative
		// to the next instruction.
		if disp, err := strconv.ParseInt(strings.TrimSuffix(arg, "(IP)"), 0, 64); err == nil {
			target := uint64(int64(in.Addr) + int64(in.Len) + disp)
			if ref, ok := n.data(target); ok {
				return ref + "(IP)"
			}
		}
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

// data resolves addr through the DataSym option, rendering the
// reference as name+offset. Resolution is trusted only for small,
// precisely-sized symbols: references into larger blobs — aggregates
// like runtime.rodata, or anonymous data attributed to whichever
// marker symbol happens to precede it — fall back to the plain masks,
// since both their offsets and their attributed names shift freely
// between builds.
func (n *norm) data(addr uint64) (ref string, ok bool) {
	if n.opts.DataSym == nil {
		return "", false
	}
	name, base, size := n.opts.DataSym(addr)
	if dataMasked(name, size) {
		return "", false
	}
	name = maskGenNumber(name)
	if addr == base {
		return name, true
	}
	return name + "+" + strconv.FormatUint(addr-base, 10), true
}

// genNumbered matches compiler-generated data symbols whose trailing
// sequence number is renumbered whenever unrelated code is added, like
// pkg..typeAssert.4 or pkg..stmp_12.
var genNumbered = regexp.MustCompile(`(\.\.[A-Za-z]+[._])\d+$`)

// maskGenNumber masks the arbitrary sequence number of generated
// symbol names so renumbering does not read as a change.
func maskGenNumber(name string) string {
	return genNumbered.ReplaceAllString(name, "$1<n>")
}

// adrpPage computes the page address an ADRP instruction produces,
// from its GoSyntax rendering "ADRP off(PC), Rd".
func adrpPage(in Inst) (uint64, bool) {
	_, rest, ok := strings.Cut(in.Text, " ")
	if !ok {
		return 0, false
	}
	first, _, _ := strings.Cut(rest, ", ")
	m := pcRel.FindStringSubmatch(first)
	if m == nil {
		return 0, false
	}
	off, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return uint64(int64(in.Addr)&^0xFFF + off), true
}
