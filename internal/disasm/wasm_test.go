package disasm_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/loov/ixdiff/internal/disasm"
	"github.com/loov/ixdiff/internal/objfile"
	"github.com/loov/ixdiff/internal/testbin"
)

func TestDecode_Wasm_KnownBody(t *testing.T) {
	body := []byte{
		0x00,       // no locals
		0x41, 0x2a, // i32.const 42
		0x1a, // drop
		0x0b, // end (implicit in the rendering: it closes the function)
	}
	insts, err := disasm.Decode(objfile.ArchWasm, body, 0, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got, want := strings.Join(opList(insts), " "), "i32.const drop"; got != want {
		t.Errorf("ops = %q, want %q", got, want)
	}
	if insts[0].Text != "i32.const 42" {
		t.Errorf("text = %q, want %q", insts[0].Text, "i32.const 42")
	}
}

func TestDecode_Wasm_RealFunctionResolvesCalls(t *testing.T) {
	bin, err := objfile.Open(testbin.Build(t, testbin.Config{GOOS: "wasip1", GOARCH: "wasm"}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	fn := bin.Funcs["main.main"]
	if fn == nil {
		t.Fatal("main.main not found")
	}
	insts, err := disasm.Decode(bin.Arch, fn.Code(), fn.Addr, disasm.Lookup(bin))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(insts) == 0 {
		t.Fatal("decoded zero instructions")
	}
	resolved := false
	for _, in := range insts {
		if in.Op == "call" && strings.Contains(in.Text, ".") {
			resolved = true
			break
		}
	}
	if !resolved {
		t.Error("no call resolved to a symbol name in main.main")
	}
}

func TestNormalize_WasmOperands(t *testing.T) {
	isAddr := func(v uint64) bool { return v >= 0x1000 && v < 0x2000 }
	insts := []disasm.Inst{
		{Addr: 1, Op: "i64.const", Text: "i64.const 4096"},
		{Addr: 2, Op: "i32.const", Text: "i32.const 8"},
		{Addr: 3, Op: "call_indirect", Text: "call_indirect (type 7)"},
		{Addr: 4, Op: "br_if", Text: "br_if 3"},
	}
	got := disasm.Normalize("f", insts, disasm.Options{IsAddr: isAddr})
	want := []string{
		"i64.const <addr>",
		"i32.const 8",
		"call_indirect (type <t>)",
		"br_if 3",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Normalize mismatch (-want +got):\n%s", diff)
	}
}
