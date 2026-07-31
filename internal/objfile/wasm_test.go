package objfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loov/ixdiff/internal/objfile"
	"github.com/loov/ixdiff/internal/testbin"
)

// TestOpen_Wasm_HugeCodeCountErrorsPromptly feeds a tiny module whose
// code section declares ~2^63 functions; it must error out promptly
// instead of spinning on the bogus count or allocating for it.
func TestOpen_Wasm_HugeCodeCountErrorsPromptly(t *testing.T) {
	count := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01} // LEB128, huge
	module := []byte("\x00asm\x01\x00\x00\x00")
	module = append(module, 10, byte(len(count))) // code section id, size
	module = append(module, count...)

	path := filepath.Join(t.TempDir(), "truncated.wasm")
	if err := os.WriteFile(path, module, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := objfile.Open(path); err == nil {
		t.Fatal("Open succeeded on a truncated code section with a huge declared count")
	}
}

func TestOpen_Wasm_FindsMainMain(t *testing.T) {
	for _, goos := range []string{"wasip1", "js"} {
		t.Run(goos, func(t *testing.T) {
			bin, err := objfile.Open(testbin.Build(t, testbin.Config{GOOS: goos, GOARCH: "wasm"}))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if bin.Arch != objfile.ArchWasm {
				t.Errorf("Arch = %v, want %v", bin.Arch, objfile.ArchWasm)
			}
			// The exact name proves pclntab recovery worked: the wasm
			// name section alone only has sanitized names.
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
			if name, ok := bin.WasmName(fn.Addr); !ok || name != "main.main" {
				t.Errorf("WasmName(%d) = %q, %v, want main.main", fn.Addr, name, ok)
			}
		})
	}
}
