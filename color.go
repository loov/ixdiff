package main

import (
	"fmt"
	"os"
	"strings"
)

// palette holds the ANSI escape codes for diff rendering; the zero
// value renders plain text.
type palette struct {
	del, ins, hunk, reset string
	// emph and unemph bracket the operands that actually changed
	// within a replaced line.
	emph, unemph string
}

// ansi is the palette used when color is enabled.
var ansi = palette{
	del:    "\x1b[31m",
	ins:    "\x1b[32m",
	hunk:   "\x1b[36m",
	reset:  "\x1b[0m",
	emph:   "\x1b[1;7m",
	unemph: "\x1b[22;27m",
}

// resolvePalette picks the palette for a --color mode: "always",
// "never", or "auto" (color when stdout is a terminal and NO_COLOR is
// unset).
func resolvePalette(mode string) (palette, error) {
	switch mode {
	case "always":
		return ansi, nil
	case "never":
		return palette{}, nil
	case "auto":
		if _, ok := os.LookupEnv("NO_COLOR"); ok {
			return palette{}, nil
		}
		if info, err := os.Stdout.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			return ansi, nil
		}
		return palette{}, nil
	default:
		return palette{}, fmt.Errorf("unknown color mode %q, expected auto, always, or never", mode)
	}
}

// paint wraps s in the given color code, or returns it unchanged for
// the plain palette.
func (pal palette) paint(color, s string) string {
	if color == "" {
		return s
	}
	return color + s + pal.reset
}

// emphasizeDiff marks the operands that differ between a replaced
// line pair, so only the actual change stands out inside the line
// colors. It reports ok=false — leaving whole-line coloring to the
// caller — when the lines do not share mnemonic and operand count, or
// when color is disabled.
func (pal palette) emphasizeDiff(oldText, newText string) (string, string, bool) {
	if pal.emph == "" {
		return "", "", false
	}
	oldOp, oldRest, ok1 := strings.Cut(oldText, " ")
	newOp, newRest, ok2 := strings.Cut(newText, " ")
	if !ok1 || !ok2 || oldOp != newOp {
		return "", "", false
	}
	// Preserve the alignment padding after the mnemonic.
	pad := len(oldRest) - len(strings.TrimLeft(oldRest, " "))
	if pad > len(newRest) {
		return "", "", false
	}
	oldArgs := strings.Split(oldRest[pad:], ", ")
	newArgs := strings.Split(newRest[pad:], ", ")
	if len(oldArgs) != len(newArgs) {
		return "", "", false
	}
	for i := range oldArgs {
		if oldArgs[i] != newArgs[i] {
			oldArgs[i] = pal.emph + oldArgs[i] + pal.unemph
			newArgs[i] = pal.emph + newArgs[i] + pal.unemph
		}
	}
	prefix := oldOp + " " + oldRest[:pad]
	return prefix + strings.Join(oldArgs, ", "), prefix + strings.Join(newArgs, ", "), true
}
