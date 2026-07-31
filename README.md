# ixdiff

ixdiff compares the assembly of two binaries to show how compiler or
build-flag changes affected the generated code: which functions
changed, by how much, and what the instruction-level differences are.

## Install

```sh
go install github.com/loov/ixdiff@latest
```

Prebuilt binaries for linux, macOS, and Windows are attached to
[releases](https://github.com/loov/ixdiff/releases).

## Usage

Summary of everything that changed:

```console
$ ixdiff tsgo.v0 tsgo.v3
functions: 5044 identical, 232 changed (+17229 relocations), 5 added, 8 removed
total text size delta: +6000 bytes

instruction delta by opcode:
    +362 MOV
    +244 LDR
     +93 BL
    ...

package delta:
       bytes    insts  changed  added  removed  package
       +2784     +699       15      0        2  syscall
        +992     +247        2      2        0  fmt
    ...

top 100 by size delta:
       bytes    insts state     function
       +1216     +304 changed   syscall.forkExec
        +608     +152 added     fmt.wrapErrorf
    ...
```

"Relocations" counts functions whose bytes differ only because code or
data moved; they are not real changes and are excluded from all
statistics.

Diff one function (`--fn` accepts substrings and suggests near
misses; repeatable):

```console
$ ixdiff --fn net/url.parseHost tsgo.v0 tsgo.v3
--- net/url.parseHost (1888 bytes)
+++ net/url.parseHost (1904 bytes)
@@ -10046b65c +10046c8ac @@
 10046b65c: ADD  $240, RSP, R2
 10046b660: ORR  $1, ZR, R3
 10046b664: MOVD R3, R4
+10046c8b8: ORR  $14, ZR, R5
 10046b668: CALL fmt.errorf(SB)
 10046b66c: CBNZ R0, L22
```

Every line carries the address of the instruction it came from, so
lines can be cross-referenced with objdump or profiler output. Added
and removed functions print their full listing.

The same diff as two columns, old on the left and new on the right:

```console
$ ixdiff --side-by-side --fn net/url.parseHost tsgo.v0 tsgo.v3
--- net/url.parseHost (1888 bytes)
+++ net/url.parseHost (1904 bytes)
@@ -10046b65c +10046c8ac @@
10046b65c: ADD  $240, RSP, R2    10046c8ac: ADD  $240, RSP, R2
10046b660: ORR  $1, ZR, R3       10046c8b0: ORR  $1, ZR, R3
10046b664: MOVD R3, R4           10046c8b4: MOVD R3, R4
                               > 10046c8b8: ORR  $14, ZR, R5
10046b668: CALL fmt.errorf(SB)   10046c8bc: CALL fmt.errorf(SB)
10046b66c: CBNZ R0, L22          10046c8c0: CBNZ R0, L22
```

Other flags:

| Flag | Effect |
| --- | --- |
| `--top N`, `--sort size\|insts\|name` | ranking table length and order |
| `--filter net/url`, `--filter ~^runtime\.` | scope the summary by substring or regexp (repeatable) |
| `--state changed\|added\|removed` | limit tables to functions in this state (repeatable) |
| `--all` | follow the summary with a diff of every ranked function |
| `--side-by-side` | two-column diff view |
| `--blocks` | match basic blocks before diffing, tolerating block reordering |
| `--mask-sp` | ignore stack-offset shifts caused by frame-size changes |
| `--json` | machine-readable output |
| `--color auto\|always\|never` | diff coloring (auto respects NO_COLOR) |
| `--version` | print the module version and VCS revision |

## How it works

1. Function ranges come from symbol tables plus the Go pclntab; pairs
   are matched by name, with renamed functions (closure renumbering,
   generic respecialization, near-identical bodies) re-paired among
   the added/removed leftovers.
2. Byte-identical pairs are skipped outright. Pairs whose
   bytes differ only in relocation fields (verified against the symbol
   tables, so a retargeted call still counts as a change) are
   classified without disassembly.
3. The rest are disassembled and normalized: call targets are
   symbolized, intra-function branches become labels derived from an
   instruction alignment (so inserting code doesn't renumber every
   label), and address-dependent operands — IP/ADRP-relative data
   references, address-valued immediates — are masked.
4. Normalized instructions are diffed per function; opcode histograms
   aggregate into the summary.

What is deliberately *not* masked: real immediates, register
allocation, instruction selection, and (by default) stack offsets —
those are the differences an optimization comparison is looking for.

## Limitations

- Instruction-level masking exists for amd64, arm64, and 386 only;
  other architectures are unsupported.
- Non-Go binaries work only as well as their symbol tables; duplicate
  static symbols (cgo) keep the last definition.
- The pclntab header magic list needs an update when a new Go release
  revs the format.

## Development

```sh
make test   # go test -race ./...
make lint   # go vet + golangci-lint (includes staticcheck)
make check  # both
```
