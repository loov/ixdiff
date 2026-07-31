package disasm_test

import (
	"strings"
	"testing"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/objfile"
	"github.com/loov/ixdiff/internal/testbin"
)

func TestDecode_AMD64_KnownBytes(t *testing.T) {
	code := []byte{
		0x48, 0x89, 0xd8, // MOVQ BX, AX
		0xe8, 0xf8, 0xff, 0xff, 0xff, // CALL .-8
		0xc3, // RET
	}
	insts, err := disasm.Decode(objfile.ArchAMD64, code, 0x1000, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ops := opList(insts)
	if got, want := strings.Join(ops, " "), "MOV CALL RET"; got != want {
		t.Errorf("ops = %q, want %q", got, want)
	}
}

func TestDecode_AMD64_UndecodableBytesBecomeBYTE(t *testing.T) {
	code := []byte{0xc3, 0x0f, 0xff} // RET followed by junk
	insts, err := disasm.Decode(objfile.ArchAMD64, code, 0, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if insts[0].Op != "RET" {
		t.Errorf("first op = %q, want RET", insts[0].Op)
	}
	total := 0
	for _, in := range insts {
		total += in.Len
		if in.Op != "RET" && in.Op != "BYTE" {
			t.Errorf("unexpected op %q for junk bytes", in.Op)
		}
	}
	if total != len(code) {
		t.Errorf("decoded lengths sum to %d, want %d", total, len(code))
	}
}

func TestDecode_386_KnownBytes(t *testing.T) {
	code := []byte{
		0x89, 0xd8, // MOVL BX, AX
		0xe8, 0xf9, 0xff, 0xff, 0xff, // CALL .-7
		0xc3, // RET
	}
	insts, err := disasm.Decode(objfile.Arch386, code, 0x1000, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got, want := strings.Join(opList(insts), " "), "MOV CALL RET"; got != want {
		t.Errorf("ops = %q, want %q", got, want)
	}
}

func TestDecode_ARM64_KnownBytes(t *testing.T) {
	code := []byte{
		0x20, 0x00, 0x80, 0xd2, // MOVD $1, R0
		0xc0, 0x03, 0x5f, 0xd6, // RET
	}
	insts, err := disasm.Decode(objfile.ArchARM64, code, 0x1000, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got, want := strings.Join(opList(insts), " "), "MOV RET"; got != want {
		t.Errorf("ops = %q, want %q", got, want)
	}
}

// TestDecode_PPC64_KnownBytes checks the same instruction words in
// both byte orders, since the two GOARCHes differ only in endianness.
func TestDecode_PPC64_KnownBytes(t *testing.T) {
	tests := []struct {
		name string
		arch objfile.Arch
		code []byte
	}{
		{"ppc64le", objfile.ArchPPC64LE, []byte{
			0x01, 0x00, 0x60, 0x38, // MOVD $1, R3 (li r3,1)
			0x20, 0x00, 0x80, 0x4e, // RET (blr)
		}},
		{"ppc64", objfile.ArchPPC64, []byte{
			0x38, 0x60, 0x00, 0x01,
			0x4e, 0x80, 0x00, 0x20,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insts, err := disasm.Decode(tt.arch, tt.code, 0x1000, nil)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got, want := strings.Join(opList(insts), " "), "MOVD RET"; got != want {
				t.Errorf("ops = %q, want %q", got, want)
			}
		})
	}
}

func TestDecode_S390X_KnownBytes(t *testing.T) {
	code := []byte{
		0xa7, 0x29, 0x00, 0x01, // LGHI $1, R2 -> MOVB $1, R2
		0x07, 0xfe, // BCR 15, R14 -> RET
	}
	insts, err := disasm.Decode(objfile.ArchS390X, code, 0x1000, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got, want := strings.Join(opList(insts), " "), "MOVB RET"; got != want {
		t.Errorf("ops = %q, want %q", got, want)
	}
}

func TestDecode_RISCV64_KnownBytes(t *testing.T) {
	code := []byte{
		0x13, 0x05, 0x10, 0x00, // ADDI $1, X0, X10
		0x67, 0x80, 0x00, 0x00, // RET (JALR X0, (X1))
	}
	insts, err := disasm.Decode(objfile.ArchRISCV64, code, 0x1000, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got, want := strings.Join(opList(insts), " "), "ADDI JALR"; got != want {
		t.Errorf("ops = %q, want %q", got, want)
	}
	if insts[1].Text != "RET" {
		t.Errorf("JALR text = %q, want RET", insts[1].Text)
	}
}

func TestDecode_RealFunction(t *testing.T) {
	tests := []struct {
		name string
		cfg  testbin.Config
	}{
		{"amd64", testbin.Config{GOOS: "linux", GOARCH: "amd64"}},
		{"arm64", testbin.Config{GOOS: "linux", GOARCH: "arm64"}},
		{"386", testbin.Config{GOOS: "linux", GOARCH: "386"}},
		{"s390x", testbin.Config{GOOS: "linux", GOARCH: "s390x"}},
		{"ppc64", testbin.Config{GOOS: "linux", GOARCH: "ppc64"}},
		{"ppc64le", testbin.Config{GOOS: "linux", GOARCH: "ppc64le"}},
		{"riscv64", testbin.Config{GOOS: "linux", GOARCH: "riscv64"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin, err := objfile.Open(testbin.Build(t, tt.cfg))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			fn := bin.Funcs["main.main"]
			if fn == nil {
				t.Fatal("main.main not found")
			}
			insts, err := disasm.Decode(bin.Arch, fn.Code(), fn.Addr, nil)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if len(insts) == 0 {
				t.Fatal("decoded zero instructions")
			}
			// Function ranges from the pclntab include trailing
			// zero padding for alignment; only non-zero bytes
			// count as decode failures.
			code := fn.Code()
			for _, in := range insts {
				if in.Op != "BYTE" {
					continue
				}
				off := in.Addr - fn.Addr
				for _, b := range code[off : off+uint64(in.Len)] {
					if b != 0 {
						t.Errorf("undecodable bytes at %#x inside main.main: %s", in.Addr, in.Text)
						break
					}
				}
			}
		})
	}
}

func opList(insts []disasm.Inst) []string {
	ops := make([]string, len(insts))
	for i, in := range insts {
		ops[i] = in.Op
	}
	return ops
}
