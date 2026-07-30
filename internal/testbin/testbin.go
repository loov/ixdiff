// Package testbin compiles the fixture program in testdata/src into
// binaries for tests. Each build configuration is compiled at most once
// per test process and shared between tests.
package testbin

import (
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// Config selects how the fixture binary is compiled.
// The zero value builds for the host platform with default flags.
type Config struct {
	GOOS    string // target OS; host OS when empty
	GOARCH  string // target architecture; host architecture when empty
	GCFlags string // passed as -gcflags
	LDFlags string // passed as -ldflags
}

// Build compiles the fixture program with cfg and returns the path to
// the resulting binary. It skips the test when the go tool is not
// available and fails it when compilation fails.
func Build(tb testing.TB, cfg Config) string {
	tb.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		tb.Skipf("go tool not available: %v", err)
	}
	path, err := cached(cfg)()
	if err != nil {
		tb.Fatalf("building fixture %+v: %v", cfg, err)
	}
	return path
}

var (
	// mu guards builds and outputDir.
	mu        sync.Mutex
	builds    = map[Config]func() (string, error){}
	outputDir string
)

// cached returns the memoized build function for cfg.
func cached(cfg Config) func() (string, error) {
	mu.Lock()
	defer mu.Unlock()
	once, ok := builds[cfg]
	if !ok {
		once = sync.OnceValues(func() (string, error) { return build(cfg) })
		builds[cfg] = once
	}
	return once
}

// build compiles the fixture program with cfg into the shared output
// directory.
func build(cfg Config) (string, error) {
	mu.Lock()
	if outputDir == "" {
		dir, err := os.MkdirTemp("", "ixdiff-testbin-*")
		if err != nil {
			mu.Unlock()
			return "", err
		}
		outputDir = dir
	}
	dir := outputDir
	mu.Unlock()

	goos, goarch := cfg.GOOS, cfg.GOARCH
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	h := fnv.New32a()
	fmt.Fprintf(h, "%+v", cfg)
	out := filepath.Join(dir, fmt.Sprintf("fixture-%08x", h.Sum32()))
	if goos == "windows" {
		out += ".exe"
	}

	args := []string{"build", "-o", out}
	if cfg.GCFlags != "" {
		args = append(args, "-gcflags", cfg.GCFlags)
	}
	if cfg.LDFlags != "" {
		args = append(args, "-ldflags", cfg.LDFlags)
	}
	args = append(args, ".")

	cmd := exec.Command("go", args...)
	cmd.Dir = sourceDir()
	cmd.Env = append(os.Environ(),
		"GOOS="+goos,
		"GOARCH="+goarch,
		"CGO_ENABLED=0",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build: %w\n%s", err, output)
	}
	return out, nil
}

// sourceDir locates testdata/src relative to this source file, so that
// Build works regardless of the test's working directory.
func sourceDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata", "src")
}
