package objfile

import "testing"

// White-box tests for the overflow and bounds hardening: the guarded
// functions are unexported and crafting hostile binaries per format is
// disproportionate, so they are exercised directly.

func TestAddFunc_RejectsSymbolWithWrappingEnd(t *testing.T) {
	b := &Binary{Funcs: map[string]*Func{}, text: make([]byte, 64), textAddr: ^uint64(0) - 32}
	// addr+size wraps past 2^64; the unhardened check let it through
	// and Code sliced out of bounds.
	b.addFunc("evil", ^uint64(0)-8, 1<<20)
	if len(b.Funcs) != 0 {
		t.Errorf("addFunc recorded a symbol whose addr+size wraps")
	}
}

func TestFunc_Code_RejectsSymbolWithWrappingEnd(t *testing.T) {
	b := &Binary{text: make([]byte, 64), textAddr: ^uint64(0) - 32}
	f := &Func{Name: "evil", Addr: ^uint64(0) - 8, Size: 1 << 20, bin: b}
	if got := f.Code(); got != nil {
		t.Errorf("Code() = %d bytes for a symbol whose addr+size wraps, want nil", len(got))
	}
}

func TestAddRange_ClampsWrappingEnd(t *testing.T) {
	b := &Binary{}
	b.addRange(^uint64(0)-16, 1<<20)
	if !b.Contains(^uint64(0) - 1) {
		t.Error("Contains lost an in-range address to end wraparound")
	}
	if b.Contains(^uint64(0) - 17) {
		t.Error("Contains reports an address below the range start")
	}
}

func TestAddSizeless_AliasedSymbolsShareExtent(t *testing.T) {
	b := &Binary{Funcs: map[string]*Func{}, text: make([]byte, 0x100), textAddr: 0x1000}
	b.addSizeless([]sizelessSym{
		{name: "a", addr: 0x1000},
		{name: "alias", addr: 0x1000},
		{name: "b", addr: 0x1080},
	})
	for _, name := range []string{"a", "alias"} {
		fn := b.Funcs[name]
		if fn == nil {
			t.Fatalf("%s not recorded", name)
		}
		if fn.Size != 0x80 {
			t.Errorf("%s size = %#x, want 0x80 (extent up to the next distinct address)", name, fn.Size)
		}
	}
}

func TestDataSym_LastZeroSizeSymbolBoundedBySection(t *testing.T) {
	b := &Binary{}
	b.addRange(0x1000, 0x100)
	b.addData("last", 0x1080, 0)
	b.finishData()
	if name, _, _ := b.DataSym(0x1090); name != "last" {
		t.Errorf("DataSym inside the section = %q, want last", name)
	}
	if name, _, _ := b.DataSym(1 << 40); name != "" {
		t.Errorf("DataSym far above every section = %q, want no match", name)
	}
}
