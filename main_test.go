package main

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zeebo/clingy"
)

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

func TestCmdDiff_Execute_RejectsUnknownSortOrder(t *testing.T) {
	got, err := parse(t, "--sort", "bogus", "a", "b")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := got.Execute(context.Background()); err == nil {
		t.Error("expected error for --sort bogus, got nil")
	}
}
