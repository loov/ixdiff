package objfile_test

import (
	"testing"

	"github.com/loov/ixdiff/internal/objfile"
	"github.com/loov/ixdiff/internal/testbin"
)

func TestOpen_MachOAndPE_FindMainMain(t *testing.T) {
	tests := []struct {
		name string
		cfg  testbin.Config
		arch objfile.Arch
	}{
		{"macho amd64", testbin.Config{GOOS: "darwin", GOARCH: "amd64"}, objfile.ArchAMD64},
		{"macho arm64", testbin.Config{GOOS: "darwin", GOARCH: "arm64"}, objfile.ArchARM64},
		{"pe amd64", testbin.Config{GOOS: "windows", GOARCH: "amd64"}, objfile.ArchAMD64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin, err := objfile.Open(testbin.Build(t, tt.cfg))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if bin.Arch != tt.arch {
				t.Errorf("Arch = %v, want %v", bin.Arch, tt.arch)
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
		})
	}
}
