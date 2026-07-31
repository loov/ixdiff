package disasm_test

import (
	"strings"
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
		"CMPQ SP, 0x10(R14)",         // register displacement kept
		"JBE L2",                     // branch -> label of RET
		"MOVQ <data>(IP), CX",        // data ref masked
		"CALL runtime.makeslice(SB)", // symbolized call kept
		"MOVL $0x1, DI",              // immediate kept
		"JMP L1",                     // self-reference -> entry label
		"RET",
	}
	got := disasm.Normalize("main.f", insts, disasm.Options{})
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
		"BLS L1",
		"MOVD $42, R0",
		"RET",
	}
	got := disasm.Normalize("main.f", insts, disasm.Options{})
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Normalize mismatch (-want +got):\n%s", diff)
	}
}

// TestNormalize_PPC64Operands covers the ppc64 absolute-address
// materialization pair: the ADDIS $0 upper half is masked as <hi> and
// the follow-up low 16 bits on the same register as <lo12>/$<lo>,
// while unrelated immediates and displacements are kept.
func TestNormalize_PPC64Operands(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x1000, Len: 4, Op: "ADDIS", Text: "ADDIS $0,$26,R5"},
		{Addr: 0x1004, Len: 4, Op: "MOVD", Text: "MOVD -21896(R5),R5"},
		{Addr: 0x1008, Len: 4, Op: "ADDIS", Text: "ADDIS $0,$13,R3"},
		{Addr: 0x100c, Len: 4, Op: "ADD", Text: "ADD R3,$-22976,R3"},
		{Addr: 0x1010, Len: 4, Op: "ADD", Text: "ADD R1,$80,R4"},
		{Addr: 0x1014, Len: 4, Op: "BLT", Text: "BLT 0x1000"},
		{Addr: 0x1018, Len: 4, Op: "RET", Text: "RET"},
	}
	want := []string{
		"ADDIS $0, <hi>, R5",
		"MOVD <lo12>(R5), R5", // low half of an ADDIS'd address
		"ADDIS $0, <hi>, R3",
		"ADD R3, $<lo>, R3", // ADD completing the pair
		"ADD R1, $80, R4",   // untracked base register kept
		"BLT L1",
		"RET",
	}
	got := disasm.Normalize("main.f", insts, disasm.Options{})
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Normalize mismatch (-want +got):\n%s", diff)
	}
}

func TestNormalize_RISCV64Operands(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x2000, Len: 4, Op: "AUIPC", Text: "AUIPC $228, X5"},
		{Addr: 0x2004, Len: 4, Op: "MOV", Text: "MOV 16(X5), X10"},
		{Addr: 0x2008, Len: 4, Op: "ADDI", Text: "ADDI $-192, X5, X7"},
		{Addr: 0x200c, Len: 4, Op: "BNE", Text: "BNE X6, X7, 2(PC)"},
		{Addr: 0x2010, Len: 4, Op: "MOV", Text: "MOV $42, X10"},
		{Addr: 0x2014, Len: 4, Op: "JALR", Text: "RET"},
	}
	want := []string{
		"AUIPC $<page>, X5",    // upper immediate masked
		"MOV <lo12>(X5), X10",  // load off the AUIPC'd register masked
		"ADDI $<lo12>, X5, X7", // low immediate completing the pair masked
		"BNE X6, X7, L1",       // branch -> label of RET
		"MOV $42, X10",         // plain immediate kept
		"RET",
	}
	got := disasm.Normalize("main.f", insts, disasm.Options{})
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Normalize mismatch (-want +got):\n%s", diff)
	}
}

// TestNormalize_LabelsStableUnderInsertion checks that inserting an
// instruction that is not a branch target does not renumber labels:
// numbering follows target order, not instruction index.
func TestNormalize_LabelsStableUnderInsertion(t *testing.T) {
	base := []disasm.Inst{
		{Addr: 0x1000, Len: 2, Op: "JBE", Text: "JBE 0x1008"},
		{Addr: 0x1002, Len: 5, Op: "MOV", Text: "MOVL $0x1, DI"},
		{Addr: 0x1007, Len: 1, Op: "NOP", Text: "NOPL"},
		{Addr: 0x1008, Len: 1, Op: "RET", Text: "RET"},
	}
	inserted := []disasm.Inst{
		{Addr: 0x1000, Len: 2, Op: "JBE", Text: "JBE 0x100d"},
		{Addr: 0x1002, Len: 5, Op: "MOV", Text: "MOVL $0x1, DI"},
		{Addr: 0x1007, Len: 5, Op: "MOV", Text: "MOVL $0x2, SI"}, // new
		{Addr: 0x100c, Len: 1, Op: "NOP", Text: "NOPL"},
		{Addr: 0x100d, Len: 1, Op: "RET", Text: "RET"},
	}
	a := disasm.Normalize("main.f", base, disasm.Options{})
	b := disasm.Normalize("main.f", inserted, disasm.Options{})
	if a[0] != "JBE L1" || b[0] != "JBE L1" {
		t.Errorf("branch labels differ despite unchanged structure: %q vs %q", a[0], b[0])
	}
}

func TestNormalize_MasksAddressImmediates(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x1000, Len: 7, Op: "MOV", Text: "MOVQ $0x4a2c40, AX"},
		{Addr: 0x1007, Len: 5, Op: "MOV", Text: "MOVL $0x1, DI"},
		{Addr: 0x100c, Len: 5, Op: "MOV", Text: "MOVL $0x4a2c40, SI"},
	}
	isAddr := func(v uint64) bool { return v >= 0x400000 && v < 0x500000 }

	got := disasm.Normalize("main.f", insts, disasm.Options{IsAddr: isAddr})
	want := []string{
		"MOVQ $<addr>, AX", // rodata pointer masked
		"MOVL $0x1, DI",    // small constant kept
		"MOVL $<addr>, SI",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("IsAddr mismatch (-want +got):\n%s", diff)
	}

	plain := disasm.Normalize("main.f", insts, disasm.Options{})
	for i, in := range insts {
		if plain[i] != in.Text {
			t.Errorf("without IsAddr rewrote %q to %q", in.Text, plain[i])
		}
	}
}

func TestNormalize_S390XOperands(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x2000, Len: 6, Op: "MOVD", Text: "MOVD 100(PC), R1"}, // larl of far data
		{Addr: 0x2006, Len: 4, Op: "BNE", Text: "BNE 2(PC)"},         // offset in 4-byte units
		{Addr: 0x200a, Len: 4, Op: "MOVB", Text: "MOVB $1, R2"},
		{Addr: 0x200e, Len: 6, Op: "BRC", Text: "BRC $7, 1(PC)"}, // offset in 6-byte units
		{Addr: 0x2014, Len: 2, Op: "RET", Text: "RET"},
	}
	want := []string{
		"MOVD <addr>(PC), R1",
		"BNE L1",
		"MOVB $1, R2",
		"BRC $7, L2",
		"RET",
	}
	got := disasm.Normalize("main.f", insts, disasm.Options{})
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Normalize mismatch (-want +got):\n%s", diff)
	}
}

func TestNormalize_MaskSP(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x1000, Len: 7, Op: "SUB", Text: "SUBQ $0x330, SP"},
		{Addr: 0x1007, Len: 8, Op: "MOV", Text: "MOVQ R11, 0x390(SP)"},
		{Addr: 0x100f, Len: 4, Op: "MOVD", Text: "MOVD.W R30, -112(RSP)"},
		{Addr: 0x1013, Len: 4, Op: "CMP", Text: "CMPQ SP, 0x10(R14)"},
		{Addr: 0x1017, Len: 4, Op: "MOV", Text: "MOV X1, 16(X2)"},
	}

	masked := disasm.Normalize("main.f", insts, disasm.Options{MaskSP: true})
	want := []string{
		"SUBQ $0x330, SP",       // frame-size immediate kept
		"MOVQ R11, <sp>(SP)",    // amd64 hex displacement masked
		"MOVD.W R30, <sp>(RSP)", // arm64 decimal displacement masked
		"CMPQ SP, 0x10(R14)",    // non-SP displacement kept
		"MOV X1, <sp>(X2)",      // riscv64 stack-pointer displacement masked
	}
	if diff := cmp.Diff(want, masked); diff != "" {
		t.Errorf("MaskSP on mismatch (-want +got):\n%s", diff)
	}

	plain := disasm.Normalize("main.f", insts, disasm.Options{})
	for i, in := range insts {
		if plain[i] != in.Text {
			t.Errorf("MaskSP off rewrote %q to %q", in.Text, plain[i])
		}
	}
}

// TestNormalize_ResolvesDataSymbols checks against real binaries that
// data references render as symbol+offset on both architectures: the
// amd64 IP-relative form and the arm64 ADRP+low12 pair (which also
// validates the ADRP page computation against GoSyntax output).
func TestNormalize_ResolvesDataSymbols(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64", "riscv64", "ppc64", "ppc64le"} {
		t.Run(arch, func(t *testing.T) {
			bin, err := objfile.Open(testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: arch}))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			fn := bin.Funcs["main.main"]
			if fn == nil {
				t.Fatal("main.main not found")
			}
			insts, err := disasm.Decode(bin.Arch, fn.Code(), fn.Addr, disasm.Lookup(bin))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			lines := disasm.Normalize(fn.Name, insts,
				disasm.Options{IsAddr: bin.Contains, DataSym: bin.DataSym})
			joined := strings.Join(lines, "\n")
			// main.main reads len(os.Args): the slice length lives 8
			// bytes past the os.Args base.
			if !strings.Contains(joined, "os.Args+8") {
				t.Errorf("expected os.Args+8 data reference in main.main:\n%s", joined)
			}
		})
	}
}

// TestNormalize_StableAcrossLayoutShifts is the property the whole
// tool depends on: a function whose source did not change must
// normalize identically even when everything around it moved. Building
// with different ldflags shifts symbol addresses without changing
// function bodies.
func TestNormalize_StableAcrossLayoutShifts(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64", "riscv64", "s390x", "ppc64", "ppc64le"} {
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
	return disasm.Normalize(fn.Name, insts, disasm.Options{IsAddr: bin.Contains})
}
