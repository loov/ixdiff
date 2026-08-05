package ixdiff

import (
	"testing"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/objfile"
)

func TestCountSpills_CountsStackReferencingInstructions(t *testing.T) {
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
			name: "arm64 RSP displacement",
			arch: objfile.ArchARM64,
			insts: []disasm.Inst{
				{Op: "MOVD", Text: "MOVD R0, -112(RSP)"},
				{Op: "MOVD", Text: "MOVD R0, R1"},
			},
			want: 1,
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
