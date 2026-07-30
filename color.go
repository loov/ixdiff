package main

import (
	"fmt"
	"os"
)

// palette holds the ANSI escape codes for diff rendering; the zero
// value renders plain text.
type palette struct {
	del, ins, hunk, reset string
}

// ansi is the palette used when color is enabled.
var ansi = palette{
	del:   "\x1b[31m",
	ins:   "\x1b[32m",
	hunk:  "\x1b[36m",
	reset: "\x1b[0m",
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
