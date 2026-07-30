package disasm_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/objfile"
	"github.com/loov/ixdiff/internal/testbin"
)

func TestNormalize_RewritesUnstableOperands(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x1000, Len: 4, Op: "CMP", Text: "CMPQ SP, 0x10(R14)"},
		{Addr: 0x1004, Len: 6, Op: "JBE", Text: "JBE 0x1020"},
		{Addr: 0x100a, Len: 7, Op: "MOV", Text: "MOVQ 0xe592f(IP), CX"},
		{Addr: 0x1011, Len: 5, Op: "CALL", Text: "CALL runtime.makeslice(SB)"},
		{Addr: 0x1016, Len: 5, Op: "MOV", Text: "MOVL $0x1, DI"},
		{Addr: 0x101b, Len: 5, Op: "JMP", Text: "JMP main.f(SB)"},
		{Addr: 0x1020, Len: 1, Op: "RET", Text: "RET"},
	}
	want := []string{
		"CMPQ SP, 0x10(R14)",           // register displacement kept
		"JBE L6",                       // branch -> label of RET
		"MOVQ <data>(IP), CX",          // data ref masked
		"CALL runtime.makeslice(SB)",   // symbolized call kept
		"MOVL $0x1, DI",                // immediate kept
		"JMP L0",                       // self-reference -> entry label
		"RET",
	}
	got := disasm.Normalize("main.f", insts)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Normalize mismatch (-want +got):\n%s", diff)
	}
}

func TestNormalize_ARM64Operands(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x2000, Len: 4, Op: "ADRP", Text: "ADRP 933888(PC), R27"},
		{Addr: 0x2004, Len: 4, Op: "BLS", Text: "BLS 2(PC)"},
		{Addr: 0x2008, Len: 4, Op: "MOVD", Text: "MOVD $42, R0"},
		{Addr: 0x200c, Len: 4, Op: "RET", Text: "RET"},
	}
	want := []string{
		"ADRP <page>(PC), R27",
		"BLS L3",
		"MOVD $42, R0",
		"RET",
	}
	got := disasm.Normalize("main.f", insts)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Normalize mismatch (-want +got):\n%s", diff)
	}
}

// TestNormalize_StableAcrossLayoutShifts is the property the whole
// tool depends on: a function whose source did not change must
// normalize identically even when everything around it moved. Building
// with different ldflags shifts symbol addresses without changing
// function bodies.
func TestNormalize_StableAcrossLayoutShifts(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			pathA := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: arch})
			pathB := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: arch, Tags: "pad"})

			binA, err := objfile.Open(pathA)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			binB, err := objfile.Open(pathB)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}

			const name = "main.main"
			a, b := binA.Funcs[name], binB.Funcs[name]
			if a == nil || b == nil {
				t.Fatalf("%s not found in both binaries", name)
			}
			if a.Addr == b.Addr {
				t.Fatal("padding did not shift the layout, test would be vacuous")
			}

			la := normalized(t, binA, a)
			lb := normalized(t, binB, b)
			if diff := cmp.Diff(la, lb); diff != "" {
				t.Errorf("normalized %s differs across layouts (-a +b):\n%s", name, diff)
			}
		})
	}
}

func normalized(t *testing.T, bin *objfile.Binary, fn *objfile.Func) []string {
	t.Helper()
	insts, err := disasm.Decode(bin.Arch, fn.Code(), fn.Addr, disasm.Lookup(bin))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return disasm.Normalize(fn.Name, insts)
}
