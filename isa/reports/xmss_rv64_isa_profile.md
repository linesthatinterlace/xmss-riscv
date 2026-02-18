# XMSS RISC-V ISA Profile

Generated: 2026-02-18 13:41:06 UTC
Toolchain: `riscv64-linux-gnu-objdump` (`GNU objdump (GNU Binutils for Ubuntu) 2.42`)
Binaries directory: `/home/jr16959/claude/xmss_jasmin/isa/binaries`

This report profiles the RISC-V ISA extensions used across all XMSS test
binaries compiled with `-march=rv64gc`.  The goal is to determine what ISA
support the Jasmin port must provide.

## Per-binary summary

| Binary | Total insn refs | Unique mnemonics |
|--------|-----------------|-----------------|
| `test_address` | 1280 | 35 |
| `test_bds` | 8313 | 55 |
| `test_bds_serial` | 9073 | 55 |
| `test_hash` | 4242 | 47 |
| `test_params` | 737 | 42 |
| `test_utils_internal` | 9959 | 55 |
| `test_wots` | 6223 | 51 |
| `test_xmss` | 9142 | 55 |
| `test_xmss_kat` | 8172 | 54 |
| `test_xmss_mt` | 9554 | 58 |
| `test_xmss_mt_kat` | 8697 | 54 |
| `test_xmss_mt_params` | 792 | 42 |

**Total across all binaries:** 76184 instruction references, 58 unique mnemonics


## Extension summary

Instruction reference counts summed across all binaries, grouped by RISC-V
ISA extension.  "Refs" counts every occurrence in every binary's disassembly
(a mnemonic appearing in a shared library pulled into multiple binaries will
be counted multiple times).  "Unique" is the number of distinct mnemonics in
that extension that appeared at least once.

| Extension | Description | Refs | Unique mnemonics | Present? |
|-----------|-------------|------|-----------------|----------|
| RV64I     | Base integer (loads, stores, branches, arith)   |  75915 |              54 | YES      |
| M         | Integer multiply/divide                         |    269 |               4 | YES      |
| A         | Atomics (lr/sc/amo)                             |      0 |               0 | no       |
| F         | Single-precision float (unexpected for XMSS)    |      0 |               0 | no       |
| D         | Double-precision float (unexpected for XMSS)    |      0 |               0 | no       |
| C         | Compressed 16-bit instructions                  |      0 |               0 | no       |
| Zb        | Bit-manipulation (Zba/Zbb/Zbc/Zbs)              |      0 |               0 | no       |
| Zicsr     | CSR read/write instructions                     |      0 |               0 | no       |
| Zifencei  | Instruction-fetch fence                         |      0 |               0 | no       |
| OTHER     | Unclassified (see section below)                |      0 |               0 | no       |


### RV64I — Base integer

Core integer operations. Always required.

| Count | Mnemonic |
|-------|----------|
|   8903 | `ld` |
|   8154 | `mv` |
|   6904 | `sd` |
|   5477 | `addi` |
|   4727 | `li` |
|   3825 | `jal` |
|   3656 | `lw` |
|   3057 | `sw` |
|   2874 | `slli` |
|   2740 | `add` |
|   2737 | `srli` |
|   2319 | `or` |
|   1928 | `xor` |
|   1886 | `auipc` |
|   1777 | `sb` |
|   1647 | `lbu` |
|   1343 | `addiw` |
|   1205 | `srliw` |
|   1113 | `slliw` |
|   1068 | `j` |
|    836 | `addw` |
|    820 | `lui` |
|    732 | `ret` |
|    631 | `bne` |
|    623 | `lwu` |
|    607 | `bnez` |
|    554 | `and` |
|    481 | `beqz` |
|    450 | `beq` |
|    357 | `bltu` |
|    350 | `bgeu` |
|    325 | `sext.w` |
|    303 | `subw` |
|    252 | `not` |
|    220 | `sub` |
|    166 | `zext.b` |
|    154 | `andi` |
|    128 | `srlw` |
|    119 | `jalr` |
|     99 | `nop` |
|     82 | `lhu` |
|     54 | `sllw` |
|     45 | `sll` |
|     42 | `srl` |
|     36 | `jr` |
|     24 | `srai` |
|     21 | `sh` |
|     17 | `negw` |
|     12 | `sgtz` |
|     12 | `ebreak` |
|     11 | `xori` |
|      9 | `ori` |
|      2 | `sraiw` |
|      1 | `blez` |


### M — Multiply/divide

Integer multiply/divide. Used by the C compiler for address arithmetic and loop induction; not directly needed by XMSS algorithm logic.

| Count | Mnemonic |
|-------|----------|
|    170 | `mulw` |
|     67 | `mul` |
|     30 | `divuw` |
|      2 | `remw` |


### A — Atomics

Not present in any binary.

### F — Single-precision float

Not present in any binary.

### D — Double-precision float

Not present in any binary.

### C — Compressed

Not present in any binary.

### Zb — Bit-manipulation (Zba/Zbb/Zbc/Zbs)

Not present in any binary.

### Zicsr — CSR instructions

Not present in any binary.

### Zifencei — Instruction-fetch fence

Not present in any binary.

### OTHER — Unclassified mnemonics

No unclassified mnemonics. All instructions were recognised.


## Implications for the Jasmin port

Based on the above profile:

1. **Required**: RV64I — always needed as the base ISA.
2. **Required if present**: M extension — if the compiler uses mul/div for
   index arithmetic, the Jasmin port must target at least RV64IM.
3. **Compressed (C)**: The Jasmin assembler will emit C instructions
   automatically when targeting rv64gc. No explicit handling needed.
4. **Atomics (A)**: Only needed if the Jasmin port uses concurrent data
   structures. XMSS algorithm code is single-threaded; A instructions
   appearing here are from libc.
5. **Float (F/D)**: Should be absent. If present, flag as a bug in the
   C implementation (possibly a compiler quirk with -march=rv64gc enabling
   float ABI).
6. **Zb (bit-manipulation)**: The C compiler with -march=rv64gc does NOT
   emit Zb instructions by default (Zb is not part of rv64gc). If the Jasmin
   port targets rv64gc_zbb (for example), it can use `ror`, `rev8`, `clz`
   explicitly for SHA-2/SHAKE — gaining performance without breaking
   compatibility with standard rv64gc hardware.

### Recommended Jasmin target ISA

- Minimum: `rv64imac` (or `rv64gc` which equals `rv64imafd_zicsr_zifencei_c`)
- Optimised: `rv64gc_zbb` to exploit Zbb rotates and byte-reversal in SHA-2

