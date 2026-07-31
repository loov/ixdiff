package objfile_test

import (
	"testing"

	"github.com/loov/ixdiff/internal/objfile"
	"github.com/loov/ixdiff/internal/testbin"
)

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
