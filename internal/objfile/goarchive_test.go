package objfile_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/fndiff"
	"github.com/loov/ixdiff/internal/objfile"
)

// buildArchive compiles a single-file package with the given body into
// a Go compile archive and returns its path. It skips the test when
// the go tool is unavailable.
func buildArchive(t *testing.T, body string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go tool not available: %v", err)
	}
	dir := t.TempDir()
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o666); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module p\n\ngo 1.26\n")
	write("p.go", "package p\n\n"+body)
	out := filepath.Join(dir, "p.a")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	return out
}

const archiveFixture = `
func Add(a, b int) int { return a + b }

func Greet(name string) string { return "hello " + name }
`

func TestOpen_GoArchive_FindsFunctions(t *testing.T) {
	bin, err := objfile.Open(buildArchive(t, archiveFixture))
	if err != nil {
		t.Fatal(err)
	}
	defer bin.Close()

	if got := bin.Arch.String(); got != runtime.GOARCH {
		t.Errorf("Arch = %v, want %v", got, runtime.GOARCH)
	}
	for _, name := range []string{"p.Add", "p.Greet"} {
		fn := bin.Funcs[name]
		if fn == nil {
			t.Fatalf("function %q not found; have %d funcs", name, len(bin.Funcs))
		}
		if fn.Size == 0 || uint64(len(fn.Code())) != fn.Size {
			t.Errorf("%s: Size = %d, len(Code()) = %d, want equal and nonzero",
				name, fn.Size, len(fn.Code()))
		}
		insts, err := disasm.Decode(bin.Arch, fn.Code(), fn.Addr, nil)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if len(insts) == 0 {
			t.Errorf("%s: decoded no instructions", name)
		}
	}
}

func TestOpen_GoArchive_CompareReportsChangedFunction(t *testing.T) {
	old, err := objfile.Open(buildArchive(t, archiveFixture))
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	new, err := objfile.Open(buildArchive(t,
		strings.Replace(archiveFixture, "a + b", "a - b", 1)))
	if err != nil {
		t.Fatal(err)
	}
	defer new.Close()

	states := map[string]fndiff.State{}
	for _, p := range fndiff.Compare(old, new) {
		states[p.Name] = p.State
	}
	if states["p.Add"] != fndiff.StateChanged {
		t.Errorf("p.Add state = %v, want changed", states["p.Add"])
	}
	if states["p.Greet"] != fndiff.StateIdentical {
		t.Errorf("p.Greet state = %v, want identical", states["p.Greet"])
	}
}

// writeArchive assembles a synthetic ar archive with a single entry
// for the error-path tests.
func writeArchive(t *testing.T, entryName, entryData string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bad.a")
	hdr := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", entryName, 0, 0, 0, 0o644, len(entryData))
	data := "!<arch>\n" + hdr + entryData
	if len(entryData)%2 != 0 {
		data += "\x00"
	}
	if err := os.WriteFile(path, []byte(data), 0o666); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpen_GoArchive_Errors(t *testing.T) {
	truncated := filepath.Join(t.TempDir(), "trunc.a")
	if err := os.WriteFile(truncated, []byte("!<arch>\ngarbage"), 0o666); err != nil {
		t.Fatal(err)
	}
	// An entry header whose declared size runs past the end of the file.
	lyingSize := filepath.Join(t.TempDir(), "lying.a")
	hdr := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", "_go_.o", 0, 0, 0, 0o644, 4096)
	if err := os.WriteFile(lyingSize, []byte("!<arch>\n"+hdr+"short"), 0o666); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{"truncated header", truncated, "truncated archive entry header"},
		{"truncated entry", lyingSize, "truncated archive entry"},
		{"truncated object header", writeArchive(t, "_go_.o", "go object linux amd64 go1.26"),
			"truncated object header"},
		{"unsupported version", writeArchive(t, "_go_.o", "go object linux amd64 go1.19\n!\n\x00go119ld"),
			"unsupported Go object version"},
		{"truncated object", writeArchive(t, "_go_.o", "go object linux amd64 go1.26\n!\n\x00go120ld"),
			"truncated object file"},
		{"unsupported arch", writeArchive(t, "_go_.o", "go object plan9 mips go1.26\n!\n\x00go120ld"),
			"unsupported architecture"},
		{"no objects", writeArchive(t, "__.PKGDEF", "go object linux amd64 go1.26\n!\n"),
			"no Go object files"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := objfile.Open(tt.path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Open = %v, want error containing %q", err, tt.want)
			}
		})
	}
}
