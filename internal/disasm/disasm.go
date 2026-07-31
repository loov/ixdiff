// Package disasm decodes machine code into assembly instructions using
// the golang.org/x/arch decoders, without spawning external tools.
package disasm

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/ppc64/ppc64asm"
	"golang.org/x/arch/riscv64/riscv64asm"
	"golang.org/x/arch/s390x/s390xasm"
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
	case objfile.ArchS390X:
		return decodeS390X(code, addr, lookup), nil
	case objfile.ArchPPC64:
		return decodePPC64(code, addr, lookup, binary.BigEndian), nil
	case objfile.ArchPPC64LE:
		return decodePPC64(code, addr, lookup, binary.LittleEndian), nil
	case objfile.ArchRISCV64:
		return decodeRISCV64(code, addr, lookup), nil
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

// decodeS390X decodes variable-length (2, 4, or 6 byte) s390x
// instructions. The mnemonic is taken from the rendered text, since
// GoSyntax rewrites raw opcodes into Go assembler names (BRASL
// becomes CALL, BCR 15 becomes RET).
func decodeS390X(code []byte, addr uint64, lookup SymLookup) []Inst {
	insts := make([]Inst, 0, len(code)/4)
	for len(code) >= 2 {
		inst, err := s390xasm.Decode(code)
		if err != nil || inst.Len == 0 || inst.Len > len(code) || inst.Op == 0 {
			insts = append(insts, byteInst(addr, code[:2]))
			code, addr = code[2:], addr+2
			continue
		}
		text := s390xasm.GoSyntax(inst, addr, lookup)
		op, _, _ := strings.Cut(text, " ")
		insts = append(insts, Inst{
			Addr: addr,
			Len:  inst.Len,
			Op:   op,
			Text: text,
		})
		code, addr = code[inst.Len:], addr+uint64(inst.Len)
	}
	if len(code) > 0 {
		insts = append(insts, byteInst(addr, code))
	}
	return insts
}

func decodePPC64(code []byte, addr uint64, lookup SymLookup, ord binary.ByteOrder) []Inst {
	insts := make([]Inst, 0, len(code)/4)
	for len(code) >= 4 {
		inst, err := ppc64asm.Decode(code, ord)
		if err != nil || inst.Len == 0 {
			insts = append(insts, byteInst(addr, code[:4]))
			code, addr = code[4:], addr+4
			continue
		}
		// The raw Op is the lowercase Power mnemonic (ld, addis);
		// take the mnemonic from the Go rendering instead (MOVD,
		// ADDIS) so ops read consistently across architectures.
		text := ppc64asm.GoSyntax(inst, addr, lookup)
		op, _, _ := strings.Cut(text, " ")
		insts = append(insts, Inst{
			Addr: addr,
			Len:  inst.Len,
			Op:   op,
			Text: text,
		})
		code, addr = code[inst.Len:], addr+uint64(inst.Len)
	}
	if len(code) > 0 {
		insts = append(insts, byteInst(addr, code))
	}
	return insts
}

func decodeRISCV64(code []byte, addr uint64, lookup SymLookup) []Inst {
	insts := make([]Inst, 0, len(code)/4)
	// Instructions are 4 bytes, or 2 with the compressed extension;
	// undecodable input advances by the 2-byte minimum unit so a
	// later compressed instruction cannot be straddled.
	for len(code) >= 2 {
		inst, err := riscv64asm.Decode(code)
		if err != nil || inst.Len == 0 {
			insts = append(insts, byteInst(addr, code[:2]))
			code, addr = code[2:], addr+2
			continue
		}
		insts = append(insts, Inst{
			Addr: addr,
			Len:  inst.Len,
			Op:   inst.Op.String(),
			Text: riscv64asm.GoSyntax(inst, addr, lookup, nil),
		})
		code, addr = code[inst.Len:], addr+uint64(inst.Len)
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
