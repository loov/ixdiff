package disasm

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/eliben/watgo"
)

// decodeWasm disassembles one wasm function body: the contents of a
// code-section entry, a locals vector followed by the expression.
// watgo decodes whole modules only, so the body is wrapped into a
// synthetic single-function module, rendered as WAT, and the printed
// instruction lines are collected back out. Call immediates resolve
// through lookup, which for wasm maps function indices, not addresses.
//
// Inst addresses are 1-based instruction ordinals and Len is zero:
// the rendering carries no per-instruction byte offsets.
func decodeWasm(code []byte, lookup SymLookup) ([]Inst, error) {
	m, err := watgo.DecodeWASM(wrapWasmBody(code))
	if err != nil {
		return nil, fmt.Errorf("decoding wasm body: %w", err)
	}
	wat, err := watgo.PrintWAT(m)
	if err != nil {
		return nil, fmt.Errorf("rendering wasm body: %w", err)
	}

	var insts []Inst
	inFunc := false
	for line := range strings.Lines(string(wat)) {
		text := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(text, "(func"):
			inFunc = true
			continue
		case !inFunc || text == "" ||
			strings.HasPrefix(text, "(") || strings.HasPrefix(text, ")"):
			continue
		}
		op, rest, _ := strings.Cut(text, " ")
		if op == "call" {
			// ponytail: only plain call is symbolized; Go does not
			// emit return_call or ref.func in function bodies.
			if idx, err := strconv.ParseUint(rest, 10, 64); err == nil {
				if name, _ := lookup(idx); name != "" {
					text = "call " + name
				}
			}
		}
		insts = append(insts, Inst{Addr: uint64(len(insts) + 1), Op: op, Text: text})
	}
	return insts, nil
}

// wrapWasmBody builds a minimal module holding body as its only
// function, under a synthetic void signature: the real signature lives
// in the original module's type section and is not needed to render
// the body.
func wrapWasmBody(body []byte) []byte {
	mod := []byte("\x00asm\x01\x00\x00\x00")
	mod = append(mod, 1, 4, 1, 0x60, 0, 0) // type section: () -> ()
	mod = append(mod, 3, 2, 1, 0)          // function section: [type 0]
	entry := appendUleb([]byte{1}, uint64(len(body)))
	entry = append(entry, body...)
	mod = append(mod, 10)
	mod = appendUleb(mod, uint64(len(entry)))
	return append(mod, entry...)
}

// appendUleb appends v as an unsigned LEB128.
func appendUleb(dst []byte, v uint64) []byte {
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		dst = append(dst, c)
		if v == 0 {
			return dst
		}
	}
}
