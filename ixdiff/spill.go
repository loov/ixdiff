package ixdiff

import (
	"strconv"
	"strings"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/objfile"
)

// pairOps are the arm64 mnemonics that move two registers per memory
// access; a stack access by one of them weighs 2 instead of 1.
var pairOps = map[string]bool{
	"LDP": true, "LDPW": true, "LDPSW": true,
	"STP": true, "STPW": true,
	"FLDPD": true, "FLDPQ": true, "FSTPD": true, "FSTPQ": true,
}

// leaOps are the mnemonics whose memory-shaped operand is address
// arithmetic, not a memory access.
var leaOps = map[string]bool{"LEAQ": true, "LEAL": true, "LEAW": true}

// spName is the stack-pointer register as it is rendered in register
// (non-memory) operands, for the architectures whose compilers
// materialize stack addresses into scratch registers. Empty for the
// rest: their stack accesses are all direct displacements.
var spName = map[objfile.Arch]string{
	objfile.ArchAMD64: "SP",
	objfile.Arch386:   "SP",
	objfile.ArchARM64: "RSP",
}

// countSpills weighs the stack accesses of insts: each instruction
// with a stack-pointer-relative memory operand counts the number of
// registers it moves (2 for arm64 paired loads and stores, 1
// otherwise). The Go compiler addresses spill slots off the stack
// pointer, so this captures register spills and reloads — but also
// stack-passed call arguments and register saves, which use the same
// addressing. The absolute count is therefore a heuristic; the delta
// between two builds of the same code isolates the code generation
// change.
//
// Frames beyond the reach of a direct displacement are addressed
// through a scratch register (arm64 ADD $off, RSP, R27; amd64
// LEAQ off(SP), DI): the defining instruction counts zero — it moves
// no data — and memory operands through the scratch register count as
// stack accesses until the register is overwritten or a call clobbers
// it.
func countSpills(arch objfile.Arch, insts []disasm.Inst) int {
	n := 0
	// alias is the set of registers currently holding a stack address.
	// ponytail: linear scan, no control flow — the compiler defines the
	// scratch register right before its uses, so joins never matter.
	alias := map[string]bool{}
	sp := spName[arch]
	for _, in := range insts {
		if in.Op == "BYTE" {
			continue
		}
		op, _, _ := strings.Cut(in.Op, ".")
		_, rest, ok := strings.Cut(in.Text, " ")
		if !ok {
			continue
		}
		// ppc64 GoSyntax joins operands with a bare comma, the other
		// architectures with comma-space; strip the optional space.
		// Paired register lists like (R0, R1) split apart, which is
		// harmless: the fragments match nothing below.
		var args []string
		for arg := range strings.SplitSeq(rest, ",") {
			args = append(args, strings.TrimPrefix(arg, " "))
		}

		if !leaOps[op] {
			for _, arg := range args {
				if disasm.IsStackRef(arch, arg) || alias[memBase(arg)] {
					if pairOps[op] {
						n += 2
					} else {
						n++
					}
					break
				}
			}
		}

		if sp == "" {
			continue
		}
		switch {
		case op == "CALL":
			clear(alias)
		case (op == "ADD" || op == "SUB") && len(args) == 3 &&
			strings.HasPrefix(args[0], "$") && args[1] == sp && args[2] != sp:
			alias[args[2]] = true
		case op == "MOVD" && len(args) == 2 && args[0] == sp && args[1] != sp:
			alias[args[1]] = true
		case leaOps[op] && len(args) == 2 && disasm.IsStackRef(arch, args[0]):
			alias[args[1]] = true
		case len(args) > 0:
			// The destination is the last operand in Go syntax; any
			// other write to a scratch register ends its alias.
			delete(alias, args[len(args)-1])
		}
	}
	return n
}

// memBase returns the base register of a rendered memory operand such
// as (R27) or -8(R27), or "" when arg is not that shape.
func memBase(arg string) string {
	if !strings.HasSuffix(arg, ")") {
		return ""
	}
	i := strings.LastIndex(arg, "(")
	if i < 0 {
		return ""
	}
	if off := arg[:i]; off != "" {
		if _, err := strconv.ParseInt(off, 0, 64); err != nil {
			return ""
		}
	}
	return arg[i+1 : len(arg)-1]
}
