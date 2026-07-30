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

func TestOpen_ELF_ARM64(t *testing.T) {
	path := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "arm64"})

	bin, err := objfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if bin.Arch != objfile.ArchARM64 {
		t.Errorf("Arch = %v, want arm64", bin.Arch)
	}
	if bin.Funcs["main.main"] == nil {
		t.Error("main.main not found")
	}
}
