package norm

import (
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// TestDecodeX86_MULXQ checks VEX-encoded MULXQ, which bits.Mul64
// compiles to at GOAMD64=v3. A decoder that does not know it reports
// the bytes as undecodable, and resuming one byte later lands inside
// the instruction and loses sync with the code. The bytes and syntax
// are from go tool objdump.
func TestDecodeX86_MULXQ(t *testing.T) {
	tests := []struct {
		code []byte
		want string
	}{
		{[]byte{0xc4, 0x62, 0xa3, 0xf6, 0xd2}, "MULXQ DX, R11, R10"},
		{[]byte{0xc4, 0x62, 0xfb, 0xf6, 0xf9}, "MULXQ CX, AX, R15"},
		{[]byte{0xc4, 0x62, 0xfb, 0xf6, 0xfe}, "MULXQ SI, AX, R15"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			in, err := decodeX86(tt.code, 64)
			if err != nil {
				t.Fatalf("decodeX86(% x): %v", tt.code, err)
			}
			if got := x86asm.GoSyntax(in, 0, nil); in.Len != len(tt.code) || got != tt.want {
				t.Errorf("decodeX86(% x) = %d-byte %q, want %d-byte %q",
					tt.code, in.Len, got, len(tt.code), tt.want)
			}
		})
	}
}

func TestDecodeX86_MULXQThenRETStaysInStep(t *testing.T) {
	code := []byte{0xc4, 0x62, 0xa3, 0xf6, 0xd2, 0xc3}
	var got []string
	for off := 0; off < len(code); {
		in, err := decodeX86(code[off:], 64)
		if err != nil {
			t.Fatalf("decodeX86 at offset %d: %v", off, err)
		}
		got = append(got, x86asm.GoSyntax(in, 0, nil))
		off += in.Len
	}
	if len(got) != 2 || got[0] != "MULXQ DX, R11, R10" || got[1] != "RET" {
		t.Errorf("decoded %q, want [MULXQ DX, R11, R10, RET]", got)
	}
}
