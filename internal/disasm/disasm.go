// Package disasm decodes machine code into assembly instructions using
// the golang.org/x/arch decoders, without spawning external tools.
package disasm

import (
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"

	"github.com/loov/ixdiff/internal/objfile"
)

// Inst is a single decoded instruction.
type Inst struct {
	Addr uint64 // virtual address of the instruction
	Len  int    // encoded length in bytes
	Op   string // mnemonic, e.g. "CALL"; "BYTE" for undecodable bytes
	Text string // full Go-syntax rendering, e.g. "CALL runtime.mallocgc(SB)"
}

// SymLookup resolves a target address to the name and base address of
// the symbol containing it, or ("", 0) when unknown. It matches the
// contract of the x/arch GoSyntax symname functions.
type SymLookup func(addr uint64) (name string, base uint64)

// Decode disassembles code, which starts at virtual address addr.
// Bytes that fail to decode become BYTE pseudo-instructions so that
// padding or data inside a function does not abort decoding.
// A nil lookup renders raw addresses.
func Decode(arch objfile.Arch, code []byte, addr uint64, lookup SymLookup) ([]Inst, error) {
	if lookup == nil {
		lookup = func(uint64) (string, uint64) { return "", 0 }
	}
	switch arch {
	case objfile.ArchAMD64:
		return decodeX86(code, addr, lookup, 64), nil
	case objfile.Arch386:
		return decodeX86(code, addr, lookup, 32), nil
	case objfile.ArchARM64:
		return decodeARM64(code, addr, lookup), nil
	default:
		return nil, fmt.Errorf("unsupported architecture %v", arch)
	}
}

// decodeX86 decodes x86 code in the given mode: 64 for amd64, 32 for 386.
func decodeX86(code []byte, addr uint64, lookup SymLookup, mode int) []Inst {
	insts := make([]Inst, 0, len(code)/4)
	for len(code) > 0 {
		inst, err := x86asm.Decode(code, mode)
		if err != nil || inst.Len == 0 || inst.Op == 0 {
			insts = append(insts, byteInst(addr, code[:1]))
			code, addr = code[1:], addr+1
			continue
		}
		insts = append(insts, Inst{
			Addr: addr,
			Len:  inst.Len,
			Op:   inst.Op.String(),
			Text: x86asm.GoSyntax(inst, addr, x86asm.SymLookup(lookup)),
		})
		code, addr = code[inst.Len:], addr+uint64(inst.Len)
	}
	return insts
}

func decodeARM64(code []byte, addr uint64, lookup SymLookup) []Inst {
	insts := make([]Inst, 0, len(code)/4)
	for len(code) >= 4 {
		inst, err := arm64asm.Decode(code)
		if err != nil {
			insts = append(insts, byteInst(addr, code[:4]))
			code, addr = code[4:], addr+4
			continue
		}
		insts = append(insts, Inst{
			Addr: addr,
			Len:  4,
			Op:   inst.Op.String(),
			Text: arm64asm.GoSyntax(inst, addr, lookup, nil),
		})
		code, addr = code[4:], addr+4
	}
	if len(code) > 0 {
		insts = append(insts, byteInst(addr, code))
	}
	return insts
}

// byteInst represents undecodable bytes as a BYTE pseudo-instruction.
func byteInst(addr uint64, raw []byte) Inst {
	return Inst{Addr: addr, Len: len(raw), Op: "BYTE", Text: fmt.Sprintf("BYTE %#x", raw)}
}
