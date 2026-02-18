# Zbb comparison: rv64gc vs rv64gc\_zbb

Compares `libxmss.a` compiled with `-march=rv64gc` (standard) and
`-march=rv64gc_zbb` (with bitmanip extensions) to quantify the impact
of Zbb on XMSS code generation.

Toolchain: `riscv64-linux-gnu-gcc` 13.3.0, `-O3`.

## Extension summary

| Extension | rv64gc | rv64gc\_zbb | Delta |
|-----------|-------:|------------:|------:|
| **I**     |   9505 |        9281 |  -224 |
| **M**     |     57 |          57 |     0 |
| **Zbb**   |      0 |         164 |  +164 |
| **Total** |   9562 |        9502 |   -60 |

The total instruction count drops by 60 (0.6%) — Zbb replaces
multi-instruction sequences (3-insn rotations, 2-insn `andn`) with
single instructions, reducing both instruction count and code size.

## Zbb instructions emitted

| Count | Mnemonic | Used in | Replaces |
|------:|----------|---------|----------|
| 41 | `rolw` | sha2\_local.c.o | `srliw` + `slliw` + `or` (32-bit rotate) |
| 28 | `andn` | sha2\_local.c.o, shake\_local.c.o, xmss\_mt.c.o | `not` + `and` |
| 27 | `rori` | sha2\_local.c.o | `srli` + `slli` + `or` (64-bit rotate-immediate) |
| 19 | `rev8` | sha2\_local.c.o | multi-insn byte-swap for endianness conversion |
| 17 | `roriw` | sha2\_local.c.o | `srliw` + `slliw` + `or` (32-bit rotate-immediate) |
| 17 | `rol` | sha2\_local.c.o, shake\_local.c.o | `srl` + `sll` + `or` (64-bit rotate) |
| 12 | `maxu` | bds.c.o, treehash.c.o, xmss\_hash.c.o | branch-based unsigned max |
|  3 | `minu` | bds.c.o, shake\_local.c.o | branch-based unsigned min |

## Where Zbb appears

| Module | Layer | Zbb insns | Zbb mnemonics |
|--------|-------|----------:|---------------|
| sha2\_local.c.o | Hash | 117 | `rolw`, `rori`, `roriw`, `rev8`, `andn` |
| shake\_local.c.o | Hash | 20 | `rol`, `andn`, `minu` |
| xmss\_hash.c.o | Hash dispatch | 5 | `maxu` |
| bds.c.o | Algorithm | 7 | `maxu`, `minu` |
| treehash.c.o | Algorithm | 4 | `maxu` |
| xmss\_mt.c.o | Algorithm | 11 | `andn` |

### Hash layer: 142 / 164 (87%)

The rotations (`rolw`, `rori`, `roriw`, `rol`) and byte-reversal (`rev8`)
appear **exclusively** in `sha2_local.c.o` — SHA-256/SHA-512 compression.
`shake_local.c.o` gets `rol` for Keccak rotations and `andn` for the
chi step (`a & ~b`).

### Algorithm layer: 22 / 164 (13%)

`maxu`/`minu` in bds.c.o and treehash.c.o replace branch-based
min/max for BDS height comparisons. `andn` in xmss\_mt.c.o replaces
a `not` + `and` pair for bitmask operations.  These are minor
optimisations — the compiler is opportunistically using Zbb where it
helps, but the algorithm doesn't structurally depend on it.

## Key takeaway

Zbb is overwhelmingly a **hash layer** optimisation.  87% of Zbb
instructions land in SHA-2 and Keccak code.  This confirms the
architecture decision: Jasmin's hash layer is the only component that
benefits from ISA-specific tuning.  Algorithm-layer code can remain
ISA-agnostic.
