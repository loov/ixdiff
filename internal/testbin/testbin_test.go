package testbin

import (
	"os"
	"testing"
)

func TestBuild_CompilesAndCaches(t *testing.T) {
	path := Build(t, Config{})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat built binary: %v", err)
	}
	if info.Size() == 0 {
		t.Error("built binary is empty")
	}
	if again := Build(t, Config{}); again != path {
		t.Errorf("same config rebuilt at different path: %q vs %q", again, path)
	}
	if other := Build(t, Config{GCFlags: "-l"}); other == path {
		t.Errorf("different config reused path %q", path)
	}
}
