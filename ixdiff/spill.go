package ixdiff

import (
	"slices"
	"strconv"
	"strings"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/objfile"
)

// pairSlots maps the arm64 mnemonics that move two registers per
// memory access to the number of 8-byte stack slots they touch: 1 for
// the 32-bit pairs, 2 for the 64-bit ones, 4 for the 128-bit ones.
var pairSlots = map[string]int{
	"LDPW": 1, "STPW": 1, "LDPSW": 1,
	"LDP": 2, "STP": 2,
	"FLDPD": 2, "FSTPD": 2,
	"FLDPQ": 4, "FSTPQ": 4,
}

// multiOps are the s390x 64-bit load/store-multiple mnemonics; a stack
// access by one of them moves and touches the length of its register
// range. The 32-bit STM/STMY forms are absent: Go's s390x linkage
// never emits them.
var multiOps = map[string]bool{"LMG": true, "STMG": true}

// vec16Ops are the amd64 16-byte vector moves: one register, two
// slots. The compiler also uses them to zero or copy stack memory in
// 16-byte blocks (MOVUPS X15, 0x28(SP) with the fixed zero register).
var vec16Ops = map[string]bool{"MOVUPS": true, "MOVOU": true, "MOVO": true}

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

// countSpills weighs the stack accesses of insts two ways.
//
// spills counts the registers moved to or from the stack: 2 for arm64
// paired loads and stores, the range length for s390x load/store-
// multiple, 1 otherwise. It tracks register-pressure events — spills
// and reloads, but also stack-passed call arguments and register
// saves, which use the same addressing.
//
// slots counts the 8-byte stack slots each access touches: 2 for a
// 16-byte access (arm64 STP, amd64 MOVUPS), 4 for a 32-byte FSTPQ,
// 1 for anything 8 bytes or narrower. It tracks memory traffic and is
// neutral under pair/vector/scalar lowering conversions that spills is
// not.
//
// Either absolute count is a heuristic; the delta between two builds
// of the same code isolates the code generation change.
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
func countSpills(arch objfile.Arch, insts []disasm.Inst) (spills, slots int) {
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
					regs, touched := weight(op, args)
					spills += regs
					slots += touched
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
	return spills, slots
}

// weight is the number of registers a stack access by op moves and
// the number of 8-byte stack slots it touches.
func weight(op string, args []string) (regs, slots int) {
	if s, ok := pairSlots[op]; ok {
		return 2, s
	}
	if vec16Ops[op] {
		return 1, 2
	}
	if multiOps[op] && len(args) == 3 {
		if a, aok := regNum(args[0]); aok {
			if b, bok := regNum(args[1]); bok {
				// The register range wraps modulo 16: STMG R14, R2
				// stores R14, R15, R0, R1, R2.
				r := (b-a+16)%16 + 1
				return r, r
			}
		}
	}
	return 1, 1
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
