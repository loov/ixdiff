package objfile_test

import (
	"bytes"
	"debug/elf"
	"os"
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
