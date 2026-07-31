package objfile_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/loov/ixdiff/internal/objfile"
	"github.com/loov/ixdiff/internal/testbin"
)

func TestOpen_ELF_FindsFunctions(t *testing.T) {
	path := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})

	bin, err := objfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if bin.Arch != objfile.ArchAMD64 {
		t.Errorf("Arch = %v, want amd64", bin.Arch)
	}
	if len(bin.Funcs) < 100 {
		t.Errorf("found only %d functions, expected a full Go binary", len(bin.Funcs))
	}

	fn := bin.Funcs["main.main"]
	if fn == nil {
		t.Fatal("main.main not found")
	}
	if fn.Size == 0 || fn.Size > 1<<20 {
		t.Errorf("main.main size = %d, out of sane range", fn.Size)
	}
	if got := uint64(len(fn.Code())); got != fn.Size {
		t.Errorf("len(Code()) = %d, want Size = %d", got, fn.Size)
	}
}

// TestOpen_HostileInputs_ErrorNotPanic feeds Open corrupt and
// unsupported files: each must produce an error, never a panic or a
// half-parsed Binary.
func TestOpen_HostileInputs_ErrorNotPanic(t *testing.T) {
	elfData, err := os.ReadFile(testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"}))
	if err != nil {
		t.Fatal(err)
	}
	// e_machine is the little-endian uint16 at offset 18 of the ELF
	// header; 0xffff is not a machine any parser supports.
	badMachine := slices.Clone(elfData)
	binary.LittleEndian.PutUint16(badMachine[18:], 0xffff)

	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{0x7f, 'E'}},
		{"not a binary", []byte("plain text, not an executable\n")},
		{"unsupported ELF machine", badMachine},
		{"truncated ELF", elfData[:len(elfData)*2/5]},
		// A code section declaring 32 payload bytes that are missing.
		{"wasm truncated section header", []byte("\x00asm\x01\x00\x00\x00\x0a\x20")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hostile.bin")
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			bin, err := objfile.Open(path)
			if err == nil {
				bin.Close()
				t.Fatal("Open succeeded on hostile input")
			}
		})
	}
}

// TestFunc_Code_MatchesFileContents checks Code() against bytes read
// directly from the file via section offsets.
func TestFunc_Code_MatchesFileContents(t *testing.T) {
	path := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64"})

	bin, err := objfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	fn := bin.Funcs["main.main"]
	if fn == nil {
		t.Fatal("main.main not found")
	}

	ef, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer ef.Close()
	text := ef.Section(".text")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	off := text.Offset + fn.Addr - text.Addr
	want := raw[off : off+fn.Size]

	if !bytes.Equal(fn.Code(), want) {
		t.Error("Code() differs from bytes at the function's file offset")
	}
}

func TestOpen_ELF_OtherArches(t *testing.T) {
	tests := []struct {
		goarch string
		want   objfile.Arch
	}{
		{"arm64", objfile.ArchARM64},
		{"386", objfile.Arch386},
		{"s390x", objfile.ArchS390X},
		{"ppc64", objfile.ArchPPC64},
		{"ppc64le", objfile.ArchPPC64LE},
	}
	for _, tt := range tests {
		t.Run(tt.goarch, func(t *testing.T) {
			path := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: tt.goarch})

			bin, err := objfile.Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if bin.Arch != tt.want {
				t.Errorf("Arch = %v, want %v", bin.Arch, tt.want)
			}
			if bin.Funcs["main.main"] == nil {
				t.Error("main.main not found")
			}
		})
	}
}

func TestOpen_ELF_RISCV64(t *testing.T) {
	path := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "riscv64"})

	bin, err := objfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if bin.Arch != objfile.ArchRISCV64 {
		t.Errorf("Arch = %v, want riscv64", bin.Arch)
	}
	if bin.Funcs["main.main"] == nil {
		t.Error("main.main not found")
	}
}

func TestOpen_ELF_Loong64(t *testing.T) {
	path := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "loong64"})

	bin, err := objfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if bin.Arch != objfile.ArchLoong64 {
		t.Errorf("Arch = %v, want loong64", bin.Arch)
	}
	if bin.Funcs["main.main"] == nil {
		t.Error("main.main not found")
	}
}

func TestOpen_ELF_ARM(t *testing.T) {
	path := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "arm"})

	bin, err := objfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if bin.Arch != objfile.ArchARM {
		t.Errorf("Arch = %v, want arm", bin.Arch)
	}
	if bin.Funcs["main.main"] == nil {
		t.Error("main.main not found")
	}
}
