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

func TestNormalize_Loong64Operands(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x2000, Len: 4, Op: "PCALAU12I", Text: "PCALAU12I $247, R30"},
		{Addr: 0x2004, Len: 4, Op: "LD.D", Text: "MOVV -1464(R30), R6"},
		{Addr: 0x2008, Len: 4, Op: "PCALAU12I", Text: "PCALAU12I $22, R4"},
		{Addr: 0x200c, Len: 4, Op: "ADDI.D", Text: "ADDV $1952, R4"},
		{Addr: 0x2010, Len: 4, Op: "BEQ", Text: "BEQ R20, 2(PC)"},
		{Addr: 0x2014, Len: 4, Op: "ADDI.D", Text: "ADDV $8, R8, R4"},
		{Addr: 0x2018, Len: 4, Op: "JIRL", Text: "RET"},
	}
	want := []string{
		"PCALAU12I $<page>, R30",
		"MOVV <lo12>(R30), R6", // load off a page register masked
		"PCALAU12I $<page>, R4",
		"ADDV $<lo12>, R4", // two-operand add completing the pair
		"BEQ R20, L1",
		"ADDV $8, R8, R4", // ordinary add kept
		"RET",
	}
	got := disasm.Normalize("main.f", insts, disasm.Options{})
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Normalize mismatch (-want +got):\n%s", diff)
	}
}

func TestNormalize_ARMOperands(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x3000, Len: 4, Op: "LDR", Text: "MOVW 0x8(R15), R0"},
		{Addr: 0x3004, Len: 4, Op: "B", Text: "B 0x3014"},
		{Addr: 0x3008, Len: 4, Op: "BL", Text: "BL runtime.makeslice(SB)"},
		{Addr: 0x300c, Len: 4, Op: "WORD", Text: "WORD $0x4a2c40"},
		{Addr: 0x3010, Len: 4, Op: "WORD", Text: "WORD $0x2a"},
		{Addr: 0x3014, Len: 4, Op: "BX", Text: "BX R14"},
	}
	isAddr := func(v uint64) bool { return v >= 0x400000 && v < 0x500000 }
	want := []string{
		"MOVW 0x8(R15), R0",        // pc-relative pool load kept
		"B L1",                     // branch -> label of BX
		"BL runtime.makeslice(SB)", // symbolized call kept
		"WORD $<addr>",             // address-valued pool word masked
		"WORD $0x2a",               // constant pool word kept
		"BX R14",
	}
	got := disasm.Normalize("main.f", insts, disasm.Options{IsAddr: isAddr})
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Normalize mismatch (-want +got):\n%s", diff)
	}
}

// TestNormalize_386Operands covers the 386 forms of address operands.
// 386 has no IP-relative addressing: globals are reached through
// absolute address immediates and absolute memory operands, both of
// which shift whenever data moves and are masked, while plain
// constants and branches keep the shared x86 treatment. The operand
// texts are real x86asm GoSyntax mode-32 renderings.
func TestNormalize_386Operands(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x1000, Len: 5, Op: "MOV", Text: "MOVL $0x4a2c40, AX"},
		{Addr: 0x1005, Len: 5, Op: "MOV", Text: "MOVL $0x1, DI"},
		{Addr: 0x100a, Len: 5, Op: "MOV", Text: "MOVL 0x4a2c40, AX"},
		{Addr: 0x100f, Len: 6, Op: "LEA", Text: "LEAL 0x4a2c40, AX"},
		{Addr: 0x1015, Len: 2, Op: "JBE", Text: "JBE 0x1018"},
		{Addr: 0x1017, Len: 1, Op: "NOP", Text: "NOPL"},
		{Addr: 0x1018, Len: 1, Op: "RET", Text: "RET"},
	}
	isAddr := func(v uint64) bool { return v >= 0x400000 && v < 0x500000 }
	want := []string{
		"MOVL $<addr>, AX", // address immediate masked via IsAddr
		"MOVL $0x1, DI",    // plain constant kept
		"MOVL <addr>, AX",  // absolute memory operand masked
		"LEAL <addr>, AX",  // absolute address materialization masked
		"JBE L1",           // branch -> label of RET
		"NOPL",
		"RET",
	}
	got := disasm.Normalize("main.f", insts, disasm.Options{IsAddr: isAddr})
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

// TestNormalize_MaskSP_PerArch checks the arch-selected stack-pointer
// patterns against operands taken from real GoSyntax output: the
// stack displacement masks while a displacement off a general register
// passes through.
func TestNormalize_MaskSP_PerArch(t *testing.T) {
	tests := []struct {
		arch objfile.Arch
		in   []string
		want []string
	}{
		{objfile.ArchAMD64,
			[]string{"MOVQ R11, 0x390(SP)", "CMPQ SP, 0x10(R14)"},
			[]string{"MOVQ R11, <sp>(SP)", "CMPQ SP, 0x10(R14)"}},
		{objfile.Arch386,
			[]string{"MOVL DX, 0x20(SP)", "MOVL AX, 0(SP)", "CMPL SP, 0x8(CX)"},
			[]string{"MOVL DX, <sp>(SP)", "MOVL AX, <sp>(SP)", "CMPL SP, 0x8(CX)"}},
		{objfile.ArchARM64,
			[]string{"MOVD.W R30, -112(RSP)", "MOVD 48(RSP), R2", "MOVD 16(R28), R16"},
			[]string{"MOVD.W R30, <sp>(RSP)", "MOVD <sp>(RSP), R2", "MOVD 16(R28), R16"}},
		{objfile.ArchARM,
			[]string{"MOVW.W R14, -0x50(R13)", "MOVW R2, 0x24(R13)", "MOVW 0x8(R10), R1"},
			[]string{"MOVW.W R14, <sp>(R13)", "MOVW R2, <sp>(R13)", "MOVW 0x8(R10), R1"}},
		{objfile.ArchRISCV64,
			[]string{"MOV X1, -104(X2)", "MOV X1, (X2)", "MOV 16(X27), X6"},
			[]string{"MOV X1, <sp>(X2)", "MOV X1, <sp>(X2)", "MOV 16(X27), X6"}},
		{objfile.ArchPPC64,
			[]string{"MOVDU R31,-128(R1)", "MOVD 72(R1),R5", "MOVD 16(R30),R22"},
			[]string{"MOVDU R31, <sp>(R1)", "MOVD <sp>(R1), R5", "MOVD 16(R30), R22"}},
		{objfile.ArchPPC64LE,
			[]string{"MOVD R0,80(R1)", "MOVD 16(R30),R22"},
			[]string{"MOVD R0, <sp>(R1)", "MOVD 16(R30), R22"}},
		{objfile.ArchLoong64,
			[]string{"MOVV R1, -104(R3)", "MOVV 48(R3), R6", "MOVV 16(R22), R20"},
			[]string{"MOVV R1, <sp>(R3)", "MOVV <sp>(R3), R6", "MOVV 16(R22), R20"}},
		{objfile.ArchS390X,
			[]string{"MOVD R14, -104(R15)", "MOVD -104(R0)(R15*1), R15", "MOVD 56(R0)(R15*1), R1", "MOVD 16(R13), R10"},
			[]string{"MOVD R14, <sp>(R15)", "MOVD <sp>(R0)(R15*1), R15", "MOVD <sp>(R0)(R15*1), R1", "MOVD 16(R13), R10"}},
	}
	for _, tt := range tests {
		t.Run(tt.arch.String(), func(t *testing.T) {
			insts := make([]disasm.Inst, len(tt.in))
			for i, text := range tt.in {
				op, _, _ := strings.Cut(text, " ")
				insts[i] = disasm.Inst{Addr: 0x1000 + uint64(i*4), Len: 4, Op: op, Text: text}
			}
			got := disasm.Normalize("main.f", insts, disasm.Options{MaskSP: true, Arch: tt.arch})
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("MaskSP mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNormalize_ResolvesDataSymbols checks against real binaries that
// data references render as symbol+offset on both architectures: the
// amd64 IP-relative form and the arm64 ADRP+low12 pair (which also
// validates the ADRP page computation against GoSyntax output).
func TestNormalize_ResolvesDataSymbols(t *testing.T) {
	// main.main reads len(os.Args): the slice length lives one pointer
	// past the os.Args base.
	// 386 is absent deliberately: its os.Args read is an absolute
	// memory operand (MOVL 0x81b1b4c, CX), which normalize masks as
	// <addr> without consulting DataSym; see TestNormalize_386Operands.
	tests := []struct {
		arch string
		want string
	}{
		{"amd64", "os.Args+8"},
		{"arm64", "os.Args+8"},
		{"arm", "os.Args+4"},
		{"riscv64", "os.Args+8"},
		{"loong64", "os.Args+8"},
		{"ppc64", "os.Args+8"},
		{"ppc64le", "os.Args+8"},
	}
	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			bin, err := objfile.Open(testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: tt.arch}))
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
			if !strings.Contains(joined, tt.want) {
				t.Errorf("expected %s data reference in main.main:\n%s", tt.want, joined)
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
	for _, cfg := range []testbin.Config{
		{GOOS: "linux", GOARCH: "amd64"},
		{GOOS: "linux", GOARCH: "386"},
		{GOOS: "linux", GOARCH: "arm64"},
		{GOOS: "linux", GOARCH: "arm"},
		{GOOS: "linux", GOARCH: "riscv64"},
		{GOOS: "linux", GOARCH: "loong64"},
		{GOOS: "linux", GOARCH: "s390x"},
		{GOOS: "linux", GOARCH: "ppc64"},
		{GOOS: "linux", GOARCH: "ppc64le"},
		{GOOS: "wasip1", GOARCH: "wasm"},
	} {
		t.Run(cfg.GOARCH, func(t *testing.T) {
			padded := cfg
			padded.Tags = "pad"
			pathA := testbin.Build(t, cfg)
			pathB := testbin.Build(t, padded)

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
	// DataSym matters: report.go always sets it, so the stability
	// property must hold with symbol resolution enabled.
	return disasm.Normalize(fn.Name, insts, disasm.Options{IsAddr: bin.Contains, DataSym: bin.DataSym})
}
