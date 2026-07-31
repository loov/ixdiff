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

func TestRelocOnly_ARM(t *testing.T) {
	// bl encodes BL to a target off bytes from the instruction; the arm
	// pc reads eight bytes ahead.
	bl := func(off int32) uint32 { return 0xEB000000 | uint32((off-8)/4)&0x00FFFFFF }
	b := func(off int32) uint32 { return 0xEA000000 | uint32((off-8)/4)&0x00FFFFFF }
	// ldrLit encodes LDR Rt, [PC, #imm]: a literal-pool load.
	ldrLit := func(rt, imm uint32) uint32 { return 0xE59F0000 | rt<<12 | imm }
	const (
		movW1 = 0xE3A00001 // MOVW $1, R0
		bxLR  = 0xE12FFF1E // BX R14
	)

	// Symbol layout mirrors the arm64 test: callee at 0x11000 (old) and
	// 0x22000 (new), otherFn at 0x13000/0x24000; functions start at
	// 0x10000/0x20000.
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
			old:  []uint32{movW1, bxLR},
			new:  []uint32{movW1, bxLR},
			want: true,
		},
		{
			// old: 0x10000 -> 0x11000 (callee), new: 0x20000 -> 0x22000 (callee)
			name: "same callee at shifted address",
			old:  []uint32{bl(0x1000), bxLR},
			new:  []uint32{bl(0x2000), bxLR},
			want: true,
		},
		{
			// old calls callee, new calls otherFn: a real change.
			name: "retargeted call",
			old:  []uint32{bl(0x1000), bxLR},
			new:  []uint32{bl(0x4000), bxLR},
			want: false,
		},
		{
			name: "branch link bit changed",
			old:  []uint32{bl(0x1000), bxLR},
			new:  []uint32{b(0x2000), bxLR},
			want: false,
		},
		{
			name: "intra-function branch retargeted",
			old:  []uint32{b(4), movW1, bxLR},
			new:  []uint32{b(8), movW1, bxLR},
			want: false,
		},
		{
			// Pool word follows the load and BX: old holds
			// globalA+0x40, new the same symbol at its shifted address.
			name: "pool word moved with same symbol",
			old:  []uint32{ldrLit(0, 0), bxLR, 0x15040},
			new:  []uint32{ldrLit(0, 0), bxLR, 0x26040},
			want: true,
		},
		{
			// old resolves globalA+0x40, new globalB+0x40: a load
			// switched to a different global is a real change.
			name: "pool word switched to different global",
			old:  []uint32{ldrLit(0, 0), bxLR, 0x15040},
			new:  []uint32{ldrLit(0, 0), bxLR, 0x26140},
			want: false,
		},
		{
			// Identical pool words, but the value resolves to globalB
			// only on the old side: still a real change.
			name: "identical pool word different symbol",
			old:  []uint32{ldrLit(0, 0), bxLR, 0x15140},
			new:  []uint32{ldrLit(0, 0), bxLR, 0x15140},
			want: false,
		},
		{
			// Neither value resolves: the fast path cannot judge how
			// raw constants render, so it must defer to full analysis.
			name: "differing unresolved pool words",
			old:  []uint32{ldrLit(0, 0), bxLR, 0x99},
			new:  []uint32{ldrLit(0, 0), bxLR, 0x9A},
			want: false,
		},
		{
			name: "real instruction change",
			old:  []uint32{movW1, bxLR},
			new:  []uint32{bxLR, bxLR},
			want: false,
		},
		{
			name: "length mismatch",
			old:  []uint32{bxLR},
			new:  []uint32{movW1, bxLR},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := disasm.RelocOnly(objfile.ArchARM,
				words(tt.old...), words(tt.new...), 0x10000, 0x20000, oldSym, newSym, oldData, newData)
			if got != tt.want {
				t.Errorf("RelocOnly = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRelocOnly_RISCV64(t *testing.T) {
	const (
		rvRet = 0x00008067 // JALR X0, (X1)
		rvNop = 0x00000013 // ADDI X0, X0, 0
		rvMov = 0x00100513 // ADDI X10, X0, 1
	)
	// jal encodes JAL rd with a signed byte offset in J-type bit order.
	jal := func(rd uint32, off int32) uint32 {
		u := uint32(off)
		return 0x6F | rd<<7 | u>>20&1<<31 | u>>1&0x3FF<<21 | u>>11&1<<20 | u>>12&0xFF<<12
	}
	call := func(off int32) uint32 { return jal(1, off) }
	auipc := func(imm20, rd uint32) uint32 { return 0x17 | rd<<7 | imm20<<12 }
	addi := func(imm int32, rs1, rd uint32) uint32 {
		return 0x13 | rd<<7 | rs1<<15 | uint32(imm)&0xFFF<<20
	}
	ld := func(imm int32, rs1, rd uint32) uint32 {
		return 0x03 | rd<<7 | 3<<12 | rs1<<15 | uint32(imm)&0xFFF<<20
	}

	// Symbol and data layout mirror the arm64 test: callee at
	// 0x11000/0x22000, otherFn at 0x13000/0x24000, globalA at
	// 0x15000/0x26000, globalB at 0x15100/0x26100; the function sits
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
			old:  []uint32{rvMov, rvRet},
			new:  []uint32{rvMov, rvRet},
			want: true,
		},
		{
			// old: 0x10000 -> 0x11000 (callee), new: 0x20000 -> 0x22000 (callee)
			name: "same callee at shifted address",
			old:  []uint32{call(0x1000), rvRet},
			new:  []uint32{call(0x2000), rvRet},
			want: true,
		},
		{
			// old calls callee, new calls otherFn: a real change.
			name: "retargeted call",
			old:  []uint32{call(0x1000), rvRet},
			new:  []uint32{call(0x4000), rvRet},
			want: false,
		},
		{
			name: "intra-function branch retargeted",
			old:  []uint32{jal(0, 4), rvNop, rvRet},
			new:  []uint32{jal(0, 8), rvNop, rvRet},
			want: false,
		},
		{
			// old: 0x10000 + 5<<12 + 0x40 = globalA+0x40; new:
			// 0x20000 + 6<<12 + 0x40 = globalA+0x40. Same symbol, moved.
			name: "auipc data ref moved with same symbol",
			old:  []uint32{auipc(5, 5), addi(0x40, 5, 10), rvRet},
			new:  []uint32{auipc(6, 5), addi(0x40, 5, 10), rvRet},
			want: true,
		},
		{
			name: "auipc load moved with same symbol",
			old:  []uint32{auipc(5, 5), ld(0x40, 5, 10), rvRet},
			new:  []uint32{auipc(6, 5), ld(0x40, 5, 10), rvRet},
			want: true,
		},
		{
			// old resolves globalA+0x40, new globalB+0x40: a load
			// switched to a different global is a real change.
			name: "auipc data ref switched to different global",
			old:  []uint32{auipc(5, 5), addi(0x40, 5, 10), rvRet},
			new:  []uint32{auipc(6, 5), addi(0x140, 5, 10), rvRet},
			want: false,
		},
		{
			// Identical words, but the same numeric address resolves
			// to different symbols per side: still a real change.
			name: "identical auipc words different symbol",
			old:  []uint32{auipc(5, 5), addi(0x140, 5, 10), rvRet},
			new:  []uint32{auipc(5, 5), addi(0x140, 5, 10), rvRet},
			want: false,
		},
		{
			name: "addi immediate differs without auipc base",
			old:  []uint32{addi(0x123, 1, 10), rvRet},
			new:  []uint32{addi(0x456, 1, 10), rvRet},
			want: false,
		},
		{
			name: "real instruction change",
			old:  []uint32{rvMov, rvRet},
			new:  []uint32{rvNop, rvRet},
			want: false,
		},
		{
			name: "length mismatch",
			old:  []uint32{rvRet},
			new:  []uint32{rvNop, rvRet},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := disasm.RelocOnly(objfile.ArchRISCV64,
				words(tt.old...), words(tt.new...), 0x10000, 0x20000, oldSym, newSym, oldData, newData)
			if got != tt.want {
				t.Errorf("RelocOnly = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRelocOnly_Loong64(t *testing.T) {
	const (
		loRet = 0x4C000020 // JIRL R0, R1, 0
		loNop = 0x03400000 // ANDI R0, R0, 0
		loOri = 0x03800404 // ORI R4, R0, 1
	)
	// b26 encodes B/BL: the 26-bit word offset is stored split, low 16
	// bits in instruction bits 25:10, high 10 bits in 9:0.
	b26 := func(opcode uint32, off int32) uint32 {
		imm := uint32(off/4) & 0x03FFFFFF
		return opcode | imm&0xFFFF<<10 | imm>>16
	}
	bl := func(off int32) uint32 { return b26(0x54000000, off) }
	b := func(off int32) uint32 { return b26(0x50000000, off) }
	pcala := func(page, rd uint32) uint32 { return 0x1A000000 | page&0xFFFFF<<5 | rd }
	addi := func(imm, rj, rd uint32) uint32 { return 0x02C00000 | imm&0xFFF<<10 | rj<<5 | rd }
	ld := func(imm, rj, rd uint32) uint32 { return 0x28C00000 | imm&0xFFF<<10 | rj<<5 | rd }

	// Symbol and data layout mirrors the arm64 test: callee at
	// 0x11000/0x22000, otherFn at 0x13000/0x24000, globalA at
	// 0x15000/0x26000, globalB at 0x15100/0x26100; the function
	// starts at 0x10000/0x20000.
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
			old:  []uint32{loOri, loRet},
			new:  []uint32{loOri, loRet},
			want: true,
		},
		{
			// old: 0x10000 -> 0x11000 (callee), new: 0x20000 -> 0x22000 (callee)
			name: "same callee at shifted address",
			old:  []uint32{bl(0x1000), loRet},
			new:  []uint32{bl(0x2000), loRet},
			want: true,
		},
		{
			// old calls callee, new calls otherFn: a real change.
			name: "retargeted call",
			old:  []uint32{bl(0x1000), loRet},
			new:  []uint32{bl(0x4000), loRet},
			want: false,
		},
		{
			name: "intra-function branch retargeted",
			old:  []uint32{b(4), loNop, loRet},
			new:  []uint32{b(8), loNop, loRet},
			want: false,
		},
		{
			// old: page 0x15000 + 0x40 = globalA+0x40; new: page
			// 0x26000 + 0x40 = globalA+0x40. Same symbol, moved.
			name: "pcalau12i data ref moved with same symbol",
			old:  []uint32{pcala(5, 27), addi(0x40, 27, 4), loRet},
			new:  []uint32{pcala(6, 27), addi(0x40, 27, 4), loRet},
			want: true,
		},
		{
			// The same page pair completed by a load instead of an add.
			name: "pcalau12i load moved with same symbol",
			old:  []uint32{pcala(5, 27), ld(0x40, 27, 4), loRet},
			new:  []uint32{pcala(6, 27), ld(0x40, 27, 4), loRet},
			want: true,
		},
		{
			// old resolves globalA+0x40, new globalB+0x40: a load
			// switched to a different global is a real change.
			name: "pcalau12i data ref switched to different global",
			old:  []uint32{pcala(5, 27), addi(0x40, 27, 4), loRet},
			new:  []uint32{pcala(6, 27), addi(0x140, 27, 4), loRet},
			want: false,
		},
		{
			// Identical words, but the same numeric page resolves to
			// different symbols per side: still a real change.
			name: "identical pcalau12i words different symbol",
			old:  []uint32{pcala(5, 27), addi(0x140, 27, 4), loRet},
			new:  []uint32{pcala(5, 27), addi(0x140, 27, 4), loRet},
			want: false,
		},
		{
			name: "add immediate differs without pcalau12i base",
			old:  []uint32{addi(0x123, 1, 4), loRet},
			new:  []uint32{addi(0x456, 1, 4), loRet},
			want: false,
		},
		{
			name: "real instruction change",
			old:  []uint32{loOri, loRet},
			new:  []uint32{loNop, loRet},
			want: false,
		},
		{
			name: "length mismatch",
			old:  []uint32{loRet},
			new:  []uint32{loNop, loRet},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := disasm.RelocOnly(objfile.ArchLoong64,
				words(tt.old...), words(tt.new...), 0x10000, 0x20000, oldSym, newSym, oldData, newData)
			if got != tt.want {
				t.Errorf("RelocOnly = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRelocOnly_386(t *testing.T) {
	// Symbol layout mirrors the amd64 test: callee at 0x11000 (old)
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
	// the end of the 5-byte instruction; the encoding is shared with
	// amd64.
	call := func(rel int32) []byte {
		return []byte{0xe8, byte(rel), byte(rel >> 8), byte(rel >> 16), byte(rel >> 24)}
	}
	movImm := func(imm int32) []byte { // MOVL $imm, AX
		return []byte{0xb8, byte(imm), byte(imm >> 8), byte(imm >> 16), byte(imm >> 24)}
	}
	movAbs := func(addr int32) []byte { // MOVL addr, AX
		return []byte{0xa1, byte(addr), byte(addr >> 8), byte(addr >> 16), byte(addr >> 24)}
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
			// 386 has no IP-relative data addressing: an absolute
			// address immediate that moved is indistinguishable from a
			// changed constant here, so the fast path must not treat it
			// as relocation noise and must defer to full analysis.
			name: "absolute address immediate differs",
			old:  cat(movImm(0x15040), ret),
			new:  cat(movImm(0x26040), ret),
			want: false,
		},
		{
			// The memory-operand form of the same shift: also opaque to
			// the fast path, so it must fail rather than mask it.
			name: "absolute memory operand differs",
			old:  cat(movAbs(0x15040), ret),
			new:  cat(movAbs(0x26040), ret),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := disasm.RelocOnly(objfile.Arch386, tt.old, tt.new,
				0x10000, 0x20000, oldSym, newSym, noData, noData)
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
