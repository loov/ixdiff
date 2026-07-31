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
			oldArgs[i], newArgs[i] = pal.emphasizeArg(oldArgs[i], newArgs[i])
		}
	}
	prefix := oldOp + " " + oldRest[:pad]
	return prefix + strings.Join(oldArgs, ", "), prefix + strings.Join(newArgs, ", "), true
}

// emphasizeArg emphasizes only the sub-tokens that differ between two
// versions of one operand, so 8(R6) against 8(R7) marks just the
// register and not the unchanged offset. Operands whose punctuation
// shapes differ are emphasized whole.
func (pal palette) emphasizeArg(old, new string) (string, string) {
	oldToks, newToks := tokenizeArg(old), tokenizeArg(new)
	same := len(oldToks) == len(newToks)
	for i := 0; same && i < len(oldToks); i++ {
		if oldToks[i] != newToks[i] && (!wordToken(oldToks[i]) || !wordToken(newToks[i])) {
			same = false
		}
	}
	if !same {
		return pal.emph + old + pal.unemph, pal.emph + new + pal.unemph
	}
	var oldOut, newOut strings.Builder
	for i := range oldToks {
		if oldToks[i] == newToks[i] {
			oldOut.WriteString(oldToks[i])
			newOut.WriteString(newToks[i])
		} else {
			oldOut.WriteString(pal.emph + oldToks[i] + pal.unemph)
			newOut.WriteString(pal.emph + newToks[i] + pal.unemph)
		}
	}
	return oldOut.String(), newOut.String()
}

// wordChar reports whether c can appear in a register, number, or
// symbol name inside an operand.
func wordChar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '_' || c == '.' || c == '$' || c == '-' || c == '#'
}

// wordToken reports whether tok is a word token rather than
// punctuation.
func wordToken(tok string) bool {
	return tok != "" && wordChar(tok[0])
}

// tokenizeArg splits an operand into alternating runs of word and
// punctuation characters: "8(R6)" becomes ["8", "(", "R6", ")"].
func tokenizeArg(s string) []string {
	var toks []string
	for i := 0; i < len(s); {
		j := i + 1
		for j < len(s) && wordChar(s[j]) == wordChar(s[i]) {
			j++
		}
		toks = append(toks, s[i:j])
		i = j
	}
	return toks
}
