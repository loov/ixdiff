package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zeebo/clingy"
)

var update = flag.Bool("update", false, "rewrite golden files")

// parse runs the clingy environment over args and captures the resolved
// command without executing it.
func parse(t *testing.T, args ...string) (*cmdDiff, error) {
	t.Helper()
	var got *cmdDiff
	_, err := clingy.Environment{
		Name: "ixdiff",
		Root: new(cmdDiff),
		Args: args,
		Wrap: func(ctx context.Context, cmd clingy.Command) error {
			got = cmd.(*cmdDiff)
			return nil
		},
		Stdout: new(strings.Builder),
		Stderr: new(strings.Builder),
	}.Run(context.Background(), nil)
	return got, err
}

func TestCmdDiff_Setup_ResolvesFlagsAndArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want cmdDiff
	}{
		{
			name: "defaults",
			args: []string{"old.bin", "new.bin"},
			want: cmdDiff{top: 100, sortBy: "size", color: "auto", oldPath: "old.bin", newPath: "new.bin"},
		},
		{
			name: "all flags",
			args: []string{"--fn", "main.main", "--top", "10", "--sort", "insts", "a", "b"},
			want: cmdDiff{fns: []string{"main.main"}, top: 10, sortBy: "insts", color: "auto", oldPath: "a", newPath: "b"},
		},
		{
			name: "repeated fn",
			args: []string{"--fn", "main.main", "--fn", "main.sum", "a", "b"},
			want: cmdDiff{fns: []string{"main.main", "main.sum"}, top: 100, sortBy: "size", color: "auto", oldPath: "a", newPath: "b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse(t, tt.args...)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if diff := cmp.Diff(&tt.want, got, cmp.AllowUnexported(cmdDiff{}, palette{})); diff != "" {
				t.Errorf("options mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHelp_MatchesGolden(t *testing.T) {
	var stdout strings.Builder
	_, err := clingy.Environment{
		Name:   "ixdiff",
		Root:   new(cmdDiff),
		Args:   []string{"-h"},
		Stdout: &stdout,
		Stderr: new(strings.Builder),
	}.Run(context.Background(), nil)
	if err != nil {
		t.Fatalf("run -h: %v", err)
	}

	golden := filepath.Join("testdata", "help.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(stdout.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(want), stdout.String()); diff != "" {
		t.Errorf("help output drifted from %s (-want +got);\nupdate README.md and rerun with -update:\n%s", golden, diff)
	}
}

func TestCmdDiff_Execute_RejectsUnknownSortOrder(t *testing.T) {
	got, err := parse(t, "--sort", "bogus", "a", "b")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := got.Execute(context.Background()); err == nil {
		t.Error("expected error for --sort bogus, got nil")
	}
}
