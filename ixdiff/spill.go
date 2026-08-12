package ixdiff

import (
	"slices"
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

// multiOps are the s390x load/store-multiple mnemonics; a stack access
// by one of them weighs the length of its register range.
var multiOps = map[string]bool{
	"LMG": true, "LMY": true, "STMG": true, "STMY": true,
}

// zero16Ops are the amd64 16-byte vector moves; storing the fixed
// zero register X15 through one is the compiler's idiom for zeroing
// two 8-byte stack slots at once and weighs 2. A vector spill from
// any other register stays at 1: it moves one register.
var zero16Ops = map[string]bool{"MOVUPS": true, "MOVOU": true, "MOVO": true}

// leaOps are the mnemonics whose memory-shaped operand is address
// arithmetic, not a memory access.
var leaOps = map[string]bool{"LEAQ": true, "LEAL": true, "LEAW": true}

// addOps are the mnemonics that yield a stack address when a source
// operand is the stack pointer: the arm64 ADD $off, RSP, R27 form, and
// the riscv64/loong64 form where the offset arrives in the destination
// register via a preceding LUI/LU12IW.
var addOps = map[string]bool{
	"ADD": true, "SUB": true,
	"ADDV": true, "ADDVU": true, "SUBV": true, "SUBVU": true,
}

// movOps are the plain register moves that copy the stack pointer into
// another register, per architecture rendering.
var movOps = map[string]bool{"MOV": true, "MOVD": true, "MOVV": true}

// spName is the stack-pointer register as it is rendered in register
// (non-memory) operands, for the architectures whose compilers
// materialize stack addresses into scratch registers. Empty for the
// rest: their stack accesses are all direct displacements.
var spName = map[objfile.Arch]string{
	objfile.ArchAMD64:   "SP",
	objfile.Arch386:     "SP",
	objfile.ArchARM64:   "RSP",
	objfile.ArchRISCV64: "X2",
	objfile.ArchLoong64: "R3",
}

// countSpills weighs the stack accesses of insts: each instruction
// with a stack-pointer-relative memory operand counts the number of
// registers it moves (2 for arm64 paired loads and stores, the range
// length for s390x load/store-multiple, 1 otherwise). The Go compiler
// addresses spill slots off the stack pointer, so this captures
// register spills and reloads — but also stack-passed call arguments
// and register saves, which use the same addressing. The absolute
// count is therefore a heuristic; the delta between two builds of the
// same code isolates the code generation change.
//
// Frames beyond the reach of a direct displacement are addressed
// through a scratch register (arm64 ADD $off, RSP, R27; amd64
// LEAQ off(SP), DI; riscv64 LUI $k, X31 then ADD X2, X31, X31;
// loong64 LU12IW $k, R30 then ADDV R3, R30): the defining instructions
// count zero — they move no data — and memory operands through the
// scratch register count as stack accesses until the register is
// overwritten or a call clobbers it.
//
// Known gaps: register-indexed stack operands (0x10(SP)(BX*8),
// (RSP)(R2)) count zero — they are stack-array traffic, not spill
// slots, and counting them would mostly add loop noise. Bulk-memory
// operations (runtime.duffzero/duffcopy calls, REP MOVS) move stack
// bytes with no per-site stack operand and are likewise invisible.
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
					n += weight(op, args)
					break
				}
			}
		}

		if sp == "" {
			continue
		}
		switch {
		case op == "CALL" || op == "JAL" || op == "JALR":
			clear(alias)
		case addOps[op] && len(args) >= 2 && last(args) != sp && slices.Contains(args[:len(args)-1], sp):
			alias[last(args)] = true
		case movOps[op] && len(args) == 2 && args[0] == sp && args[1] != sp:
			alias[args[1]] = true
		case leaOps[op] && len(args) == 2 && disasm.IsStackRef(arch, args[0]):
			alias[args[1]] = true
		case len(args) > 0:
			// The destination is the last operand in Go syntax; any
			// other write to a scratch register ends its alias.
			delete(alias, last(args))
		}
	}
	return n
}

// weight is the number of registers a stack access by op moves.
func weight(op string, args []string) int {
	if pairOps[op] {
		return 2
	}
	if zero16Ops[op] && len(args) > 0 && args[0] == "X15" {
		return 2
	}
	if multiOps[op] && len(args) == 3 {
		if a, aok := regNum(args[0]); aok {
			if b, bok := regNum(args[1]); bok {
				// The register range wraps modulo 16: STMG R14, R2
				// stores R14, R15, R0, R1, R2.
				return (b-a+16)%16 + 1
			}
		}
	}
	return 1
}

// regNum returns the number of a rendered s390x general register.
func regNum(s string) (int, bool) {
	num, ok := strings.CutPrefix(s, "R")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(num)
	return n, err == nil && n < 16
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

// last returns the final operand: the destination in Go syntax.
func last(args []string) string {
	return args[len(args)-1]
}
