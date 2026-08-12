package ixdiff

import (
	"testing"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/objfile"
)

func TestCountSpills_WeightsRegistersAndSlots(t *testing.T) {
	tests := []struct {
		name       string
		arch       objfile.Arch
		insts      []disasm.Inst
		wantSpills int
		wantSlots  int
	}{
		{
			name: "amd64 store, reload, and non-stack ops",
			arch: objfile.ArchAMD64,
			insts: []disasm.Inst{
				{Op: "MOVQ", Text: "MOVQ AX, 0x10(SP)"},
				{Op: "MOVQ", Text: "MOVQ 0x10(SP), AX"},
				{Op: "MOVQ", Text: "MOVQ AX, BX"},
				{Op: "LEAQ", Text: "LEAQ 0x8(AX), BX"},
				{Op: "RET", Text: "RET"},
			},
			wantSpills: 2,
			wantSlots:  2,
		},
		{
			name: "amd64 zero-offset and both-operand count once",
			arch: objfile.ArchAMD64,
			insts: []disasm.Inst{
				{Op: "MOVQ", Text: "MOVQ (SP), AX"},
				{Op: "ADDQ", Text: "ADDQ 0x8(SP), 0x10(SP)"},
			},
			wantSpills: 2,
			wantSlots:  2,
		},
		{
			name: "amd64 excludes BYTE padding",
			arch: objfile.ArchAMD64,
			insts: []disasm.Inst{
				{Op: "BYTE", Text: "BYTE 0x10(SP)"},
			},
			wantSpills: 0,
			wantSlots:  0,
		},
		{
			name: "amd64 LEA is address arithmetic, store through it counts",
			arch: objfile.ArchAMD64,
			insts: []disasm.Inst{
				{Op: "LEAQ", Text: "LEAQ 0x10(SP), DI"},
				{Op: "MOVQ", Text: "MOVQ AX, (DI)"},
			},
			wantSpills: 1,
			wantSlots:  1,
		},
		{
			name: "amd64 overwriting the scratch register ends its alias",
			arch: objfile.ArchAMD64,
			insts: []disasm.Inst{
				{Op: "LEAQ", Text: "LEAQ 0x10(SP), DI"},
				{Op: "MOVQ", Text: "MOVQ $0x1, DI"},
				{Op: "MOVQ", Text: "MOVQ AX, (DI)"},
			},
			wantSpills: 0,
			wantSlots:  0,
		},
		{
			name: "amd64 vector store moves one register, touches two slots",
			arch: objfile.ArchAMD64,
			insts: []disasm.Inst{
				{Op: "MOVUPS", Text: "MOVUPS X15, 0x28(SP)"},
				{Op: "MOVUPS", Text: "MOVUPS X0, 0x38(SP)"},
			},
			wantSpills: 2,
			wantSlots:  4,
		},
		{
			name: "arm64 RSP displacement",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "MOVD", Text: "MOVD R0, -112(RSP)"},
				{Op: "MOVD", Text: "MOVD R0, R1"},
			},
			wantSpills: 1,
			wantSlots:  1,
		},
		{
			name: "arm64 pairs weigh registers and slots by width",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "STP", Text: "STP (R0, R1), 8(RSP)"},
				{Op: "STPW", Text: "STPW (R0, R1), 8(RSP)"},
				{Op: "FLDPQ", Text: "FLDPQ 16(RSP), (F0, F1)"},
			},
			wantSpills: 6, // 2 registers each
			wantSlots:  7, // 2 + 1 + 4
		},
		{
			name: "arm64 scratch-mediated pair matches direct split stores",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "ADD", Text: "ADD $600, RSP, R27"},
				{Op: "STP", Text: "STP (R0, R1), (R27)"},
			},
			wantSpills: 2, // same as MOVD R0, 600(RSP); MOVD R1, 608(RSP)
			wantSlots:  2,
		},
		{
			name: "arm64 SP copy makes the register a stack base",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "MOVD", Text: "MOVD RSP, R20"},
				{Op: "MOVD", Text: "MOVD R0, -8(R20)"},
			},
			wantSpills: 1,
			wantSlots:  1,
		},
		{
			name: "arm64 call clobbers scratch aliases",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "ADD", Text: "ADD $600, RSP, R27"},
				{Op: "CALL", Text: "CALL runtime.morestack(SB)"},
				{Op: "MOVD", Text: "MOVD R0, (R27)"},
			},
			wantSpills: 0,
			wantSlots:  0,
		},
		{
			name: "arm64 non-stack pair does not count",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "STP", Text: "STP (R0, R1), (R2)"},
			},
			wantSpills: 0,
			wantSlots:  0,
		},
		{
			name: "riscv64 scratch-mediated big-frame store",
			arch: objfile.ArchRISCV64,
			insts: []disasm.Inst{
				{Op: "LUI", Text: "LUI $4294967292, X31"},
				{Op: "ADD", Text: "ADD X2, X31, X31"},
				{Op: "MOV", Text: "MOV X1, 1200(X31)"},
				{Op: "MOV", Text: "MOV X1, 16(X2)"},
			},
			wantSpills: 2,
			wantSlots:  2,
		},
		{
			name: "riscv64 JAL clobbers scratch aliases",
			arch: objfile.ArchRISCV64,
			insts: []disasm.Inst{
				{Op: "ADD", Text: "ADD X2, X31, X31"},
				{Op: "JAL", Text: "JAL X5, runtime.morestack_noctxt.abi0(SB)"},
				{Op: "MOV", Text: "MOV X1, 1200(X31)"},
			},
			wantSpills: 0,
			wantSlots:  0,
		},
		{
			name: "loong64 scratch-mediated big-frame store and reload",
			arch: objfile.ArchLoong64,
			insts: []disasm.Inst{
				{Op: "LU12IW", Text: "LU12IW $-5, R30"},
				{Op: "ADDV", Text: "ADDV R3, R30"},
				{Op: "MOVV", Text: "MOVV R1, 1200(R30)"},
				{Op: "MOVV", Text: "MOVV -1208(R30), R7"},
			},
			wantSpills: 2,
			wantSlots:  2,
		},
		{
			name: "s390x store-multiple counts its register range",
			arch: objfile.ArchS390X,
			insts: []disasm.Inst{
				{Op: "STMG", Text: "STMG R1, R4, 48(R15)"},
				{Op: "LMG", Text: "LMG R14, R2, 216(R15)"},
				{Op: "STMG", Text: "STMG R1, R2, (R7)"},
			},
			wantSpills: 9, // 4 + 5 (R14, R15, R0, R1, R2), non-stack STMG excluded
			wantSlots:  9,
		},
		{
			name: "wasm has no stack pointer",
			arch: objfile.ArchWasm,
			insts: []disasm.Inst{
				{Op: "i32.const", Text: "i32.const 16"},
			},
			wantSpills: 0,
			wantSlots:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spills, slots := countSpills(tt.arch, tt.insts)
			if spills != tt.wantSpills || slots != tt.wantSlots {
				t.Errorf("countSpills = (%d, %d), want (%d, %d)",
					spills, slots, tt.wantSpills, tt.wantSlots)
			}
		})
	}
}
