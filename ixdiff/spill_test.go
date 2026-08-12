package ixdiff

import (
	"testing"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/objfile"
)

func TestCountSpills_WeightsStackAccesses(t *testing.T) {
	tests := []struct {
		name  string
		arch  objfile.Arch
		insts []disasm.Inst
		want  int
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
			want: 2,
		},
		{
			name: "amd64 zero-offset and both-operand count once",
			arch: objfile.ArchAMD64,
			insts: []disasm.Inst{
				{Op: "MOVQ", Text: "MOVQ (SP), AX"},
				{Op: "ADDQ", Text: "ADDQ 0x8(SP), 0x10(SP)"},
			},
			want: 2,
		},
		{
			name: "amd64 excludes BYTE padding",
			arch: objfile.ArchAMD64,
			insts: []disasm.Inst{
				{Op: "BYTE", Text: "BYTE 0x10(SP)"},
			},
			want: 0,
		},
		{
			name: "amd64 LEA is address arithmetic, store through it counts",
			arch: objfile.ArchAMD64,
			insts: []disasm.Inst{
				{Op: "LEAQ", Text: "LEAQ 0x10(SP), DI"},
				{Op: "MOVQ", Text: "MOVQ AX, (DI)"},
			},
			want: 1,
		},
		{
			name: "amd64 overwriting the scratch register ends its alias",
			arch: objfile.ArchAMD64,
			insts: []disasm.Inst{
				{Op: "LEAQ", Text: "LEAQ 0x10(SP), DI"},
				{Op: "MOVQ", Text: "MOVQ $0x1, DI"},
				{Op: "MOVQ", Text: "MOVQ AX, (DI)"},
			},
			want: 0,
		},
		{
			name: "arm64 RSP displacement",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "MOVD", Text: "MOVD R0, -112(RSP)"},
				{Op: "MOVD", Text: "MOVD R0, R1"},
			},
			want: 1,
		},
		{
			name: "arm64 paired store counts both registers",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "STP", Text: "STP (R0, R1), 8(RSP)"},
				{Op: "FLDPQ", Text: "FLDPQ 16(RSP), (F0, F1)"},
			},
			want: 4,
		},
		{
			name: "arm64 scratch-mediated pair matches direct split stores",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "ADD", Text: "ADD $600, RSP, R27"},
				{Op: "STP", Text: "STP (R0, R1), (R27)"},
			},
			want: 2, // same as MOVD R0, 600(RSP); MOVD R1, 608(RSP)
		},
		{
			name: "arm64 SP copy makes the register a stack base",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "MOVD", Text: "MOVD RSP, R20"},
				{Op: "MOVD", Text: "MOVD R0, -8(R20)"},
			},
			want: 1,
		},
		{
			name: "arm64 call clobbers scratch aliases",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "ADD", Text: "ADD $600, RSP, R27"},
				{Op: "CALL", Text: "CALL runtime.morestack(SB)"},
				{Op: "MOVD", Text: "MOVD R0, (R27)"},
			},
			want: 0,
		},
		{
			name: "arm64 non-stack pair does not count",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "STP", Text: "STP (R0, R1), (R2)"},
			},
			want: 0,
		},
		{
			name: "wasm has no stack pointer",
			arch: objfile.ArchWasm,
			insts: []disasm.Inst{
				{Op: "i32.const", Text: "i32.const 16"},
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := countSpills(tt.arch, tt.insts); got != tt.want {
				t.Errorf("countSpills = %d, want %d", got, tt.want)
			}
		})
	}
}
