package objfile_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/loov/ixdiff/internal/objfile"
	"github.com/loov/ixdiff/internal/testbin"
)

// TestOpen_StrippedBinaries_StillFindFunctions checks that function
// ranges come from the pclntab when the symbol table is stripped.
func TestOpen_StrippedBinaries_StillFindFunctions(t *testing.T) {
	tests := []struct {
		name string
		cfg  testbin.Config
	}{
		{"elf", testbin.Config{GOOS: "linux", GOARCH: "amd64", LDFlags: "-s -w"}},
		{"macho", testbin.Config{GOOS: "darwin", GOARCH: "arm64", LDFlags: "-s -w"}},
		{"pe", testbin.Config{GOOS: "windows", GOARCH: "amd64", LDFlags: "-s -w"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin, err := objfile.Open(testbin.Build(t, tt.cfg))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			fn := bin.Funcs["main.main"]
			if fn == nil {
				t.Fatal("main.main not found in stripped binary")
			}
			if fn.Size == 0 || fn.Size > 1<<20 {
				t.Errorf("main.main size = %d, out of sane range", fn.Size)
			}
			if got := uint64(len(fn.Code())); got != fn.Size {
				t.Errorf("len(Code()) = %d, want Size = %d", got, fn.Size)
			}
		})
	}
}

// TestOpen_ELFWithoutPclntabSection_FindsFunctionsByScan checks that
// function ranges are still recovered when the ELF has no .gopclntab
// section, as with externally linked (cgo) binaries where the system
// linker merges the pclntab into another data section. The fixture
// simulates that layout by renaming the section in a stripped binary,
// leaving the pclntab bytes findable only by scanning.
func TestOpen_ELFWithoutPclntabSection_FindsFunctionsByScan(t *testing.T) {
	path := testbin.Build(t, testbin.Config{GOOS: "linux", GOARCH: "amd64", LDFlags: "-s -w"})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	i := bytes.Index(data, []byte(".gopclntab\x00"))
	if i < 0 {
		t.Fatal("fixture has no .gopclntab section name to rename")
	}
	data[i] = 'X'
	patched := filepath.Join(t.TempDir(), "renamed.elf")
	if err := os.WriteFile(patched, data, 0o755); err != nil {
		t.Fatal(err)
	}

	bin, err := objfile.Open(patched)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer bin.Close()
	fn := bin.Funcs["main.main"]
	if fn == nil {
		t.Fatal("main.main not found without a .gopclntab section")
	}
	if fn.Size == 0 || fn.Size > 1<<20 {
		t.Errorf("main.main size = %d, out of sane range", fn.Size)
	}
}

// TestOpen_PclntabOverridesInferredSizes checks that Mach-O sizes come
// from the pclntab rather than next-symbol inference: an inferred size
// includes alignment padding up to the next symbol, an exact one ends
// at the last instruction.
func TestOpen_PclntabOverridesInferredSizes(t *testing.T) {
	bin, err := objfile.Open(testbin.Build(t, testbin.Config{GOOS: "darwin", GOARCH: "arm64"}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	unaligned := 0
	for _, fn := range bin.Funcs {
		if fn.Size%16 != 0 {
			unaligned++
		}
	}
	// With purely inferred sizes nearly every size would be a
	// multiple of the 16-byte function alignment.
	if unaligned == 0 {
		t.Error("all function sizes are 16-byte aligned, sizes look inferred rather than exact")
	}
}
