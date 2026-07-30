package disasm_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/objfile"
)

// words builds little-endian arm64 code from instruction words.
func words(ws ...uint32) []byte {
	out := make([]byte, 4*len(ws))
	for i, w := range ws {
		binary.LittleEndian.PutUint32(out[4*i:], w)
	}
	return out
}

const (
	ret  = 0xd65f03c0
	nop  = 0xd503201f
	movX = 0xd2800020 // MOVZ X0, #1
)

func TestRelocOnly_ARM64(t *testing.T) {
	bl := func(off int32) uint32 { return 0x94000000 | uint32(off/4)&0x03FFFFFF }
	adrp := func(page uint32, rd uint32) uint32 { return 0x90000000 | (page&3)<<29 | (page>>2&0x7FFFF)<<5 | rd }
	addImm := func(imm, rn, rd uint32) uint32 { return 0x91000000 | imm<<10 | rn<<5 | rd }

	// Symbol layout: old side has callee at 0x11000, new side at
	// 0x22000; a second function otherFn sits at 0x13000/0x24000.
	oldSym := func(addr uint64) (string, uint64) {
		switch {
		case addr >= 0x11000 && addr < 0x12000:
			return "callee", 0x11000
		case addr >= 0x13000 && addr < 0x14000:
			return "otherFn", 0x13000
		}
		return "", 0
	}
	newSym := func(addr uint64) (string, uint64) {
		switch {
		case addr >= 0x22000 && addr < 0x23000:
			return "callee", 0x22000
		case addr >= 0x24000 && addr < 0x25000:
			return "otherFn", 0x24000
		}
		return "", 0
	}

	// Data layout: old side has a global at 0x15000, new at 0x26000;
	// a second global sits at 0x15100/0x26100.
	oldData := func(addr uint64) (string, uint64, uint64) {
		switch {
		case addr >= 0x15000 && addr < 0x15100:
			return "globalA", 0x15000, 0x100
		case addr >= 0x15100 && addr < 0x15200:
			return "globalB", 0x15100, 0x100
		}
		return "", 0, 0
	}
	newData := func(addr uint64) (string, uint64, uint64) {
		switch {
		case addr >= 0x26000 && addr < 0x26100:
			return "globalA", 0x26000, 0x100
		case addr >= 0x26100 && addr < 0x26200:
			return "globalB", 0x26100, 0x100
		}
		return "", 0, 0
	}

	tests := []struct {
		name     string
		old, new []uint32
		want     bool
	}{
		{
			name: "identical",
			old:  []uint32{movX, ret},
			new:  []uint32{movX, ret},
			want: true,
		},
		{
			// old: 0x10000 -> 0x11000 (callee), new: 0x20000 -> 0x22000 (callee)
			name: "same callee at shifted address",
			old:  []uint32{bl(0x1000), ret},
			new:  []uint32{bl(0x2000), ret},
			want: true,
		},
		{
			// old calls callee, new calls otherFn: a real change.
			name: "retargeted call",
			old:  []uint32{bl(0x1000), ret},
			new:  []uint32{bl(0x4000), ret},
			want: false,
		},
		{
			name: "intra-function branch retargeted",
			old:  []uint32{0x14000001, nop, ret}, // B +4
			new:  []uint32{0x14000002, nop, ret}, // B +8
			want: false,
		},
		{
			// old: page 0x15000 + 0x40 = globalA+0x40; new: page
			// 0x26000 + 0x40 = globalA+0x40. Same symbol, moved.
			name: "adrp data ref moved with same symbol",
			old:  []uint32{adrp(5, 27), addImm(0x40, 27, 0), ret},
			new:  []uint32{adrp(6, 27), addImm(0x40, 27, 0), ret},
			want: true,
		},
		{
			// old resolves globalA+0x40, new globalB+0x40: a load
			// switched to a different global is a real change.
			name: "adrp data ref switched to different global",
			old:  []uint32{adrp(5, 27), addImm(0x40, 27, 0), ret},
			new:  []uint32{adrp(6, 27), addImm(0x140, 27, 0), ret},
			want: false,
		},
		{
			// Identical words, but the same numeric page resolves to
			// different symbols per side: still a real change.
			name: "identical adrp words different symbol",
			old:  []uint32{adrp(5, 27), addImm(0x140, 27, 0), ret},
			new:  []uint32{adrp(5, 27), addImm(0x140, 27, 0), ret},
			want: false,
		},
		{
			name: "add immediate differs without adrp base",
			old:  []uint32{addImm(0x123, 1, 0), ret},
			new:  []uint32{addImm(0x456, 1, 0), ret},
			want: false,
		},
		{
			name: "real instruction change",
			old:  []uint32{movX, ret},
			new:  []uint32{nop, ret},
			want: false,
		},
		{
			name: "length mismatch",
			old:  []uint32{ret},
			new:  []uint32{nop, ret},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := disasm.RelocOnly(objfile.ArchARM64,
				words(tt.old...), words(tt.new...), 0x10000, 0x20000, oldSym, newSym, oldData, newData)
			if got != tt.want {
				t.Errorf("RelocOnly = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRelocOnly_AMD64(t *testing.T) {
	// Symbol layout mirrors the arm64 test: callee at 0x11000 (old)
	// and 0x22000 (new), otherFn at 0x13000/0x24000; functions start
	// at 0x10000/0x20000.
	oldSym := func(addr uint64) (string, uint64) {
		switch {
		case addr >= 0x11000 && addr < 0x12000:
			return "callee", 0x11000
		case addr >= 0x13000 && addr < 0x14000:
			return "otherFn", 0x13000
		}
		return "", 0
	}
	newSym := func(addr uint64) (string, uint64) {
		switch {
		case addr >= 0x22000 && addr < 0x23000:
			return "callee", 0x22000
		case addr >= 0x24000 && addr < 0x25000:
			return "otherFn", 0x24000
		}
		return "", 0
	}
	noData := func(uint64) (string, uint64, uint64) { return "", 0, 0 }

	// call rel32 encodes CALL with a little-endian displacement from
	// the end of the 5-byte instruction.
	call := func(rel int32) []byte {
		return []byte{0xe8, byte(rel), byte(rel >> 8), byte(rel >> 16), byte(rel >> 24)}
	}
	lea := func(disp int32) []byte { // LEAQ disp(IP), AX
		return []byte{0x48, 0x8d, 0x05, byte(disp), byte(disp >> 8), byte(disp >> 16), byte(disp >> 24)}
	}
	ret := []byte{0xc3}
	cat := func(bs ...[]byte) []byte { return bytes.Join(bs, nil) }

	tests := []struct {
		name     string
		old, new []byte
		want     bool
	}{
		{
			// old: 0x10005+0xffb = 0x11000 (callee); new: 0x20005+0x1ffb = 0x22000.
			name: "same callee at shifted address",
			old:  cat(call(0xffb), ret),
			new:  cat(call(0x1ffb), ret),
			want: true,
		},
		{
			// new calls otherFn at 0x24000 instead.
			name: "retargeted call",
			old:  cat(call(0xffb), ret),
			new:  cat(call(0x3ffb), ret),
			want: false,
		},
		{
			// Unresolved RIP-relative data on both sides masks alike.
			name: "rip-relative displacement differs",
			old:  cat(lea(0x100), ret),
			new:  cat(lea(0x200), ret),
			want: true,
		},
		{
			// MOVL $1 vs $2: a real immediate change.
			name: "immediate differs",
			old:  cat([]byte{0xbf, 1, 0, 0, 0}, ret),
			new:  cat([]byte{0xbf, 2, 0, 0, 0}, ret),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := disasm.RelocOnly(objfile.ArchAMD64, tt.old, tt.new,
				0x10000, 0x20000, oldSym, newSym, noData, noData)
			if got != tt.want {
				t.Errorf("RelocOnly = %v, want %v", got, tt.want)
			}
		})
	}
}
