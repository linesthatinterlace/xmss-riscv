# isa/ — RISC-V ISA profiling for the XMSS C implementation

This directory contains tooling to determine which RISC-V ISA extensions are
actually exercised by the XMSS C implementation when compiled with the
standard `rv64gc` toolchain.  The results inform what ISA support the planned
Jasmin port must provide.

## Directory layout

```
isa/
  binaries/     RISC-V ELF test binaries (copied here from impl/c/build-rv/)
  scripts/      Analysis scripts
  reports/      Generated Markdown reports (output of the analysis)
```

## Step 1 — Build the RISC-V binaries

From the `impl/c/` directory, run the RISC-V cross-compile target:

```bash
cd impl/c
make rv
```

This invokes CMake with `cmake/toolchain-riscv64.cmake` which uses
`riscv64-linux-gnu-gcc -march=rv64gc -mabi=lp64d`.  The resulting ELF
binaries are placed in `impl/c/build-rv/test/`.

Then copy them into `isa/binaries/`:

```bash
cp impl/c/build-rv/test/test_* isa/binaries/
```

The expected binaries (matching the test suite as of this writing) are:

| Binary | What it tests |
|--------|--------------|
| `test_params` | All 12 XMSS OIDs |
| `test_address` | ADRS serialisation |
| `test_hash` | SHA-256, SHA-512, SHAKE-128, SHAKE-256 |
| `test_wots` | WOTS+ sign/verify roundtrip |
| `test_xmss` | BDS keygen/sign/verify roundtrip |
| `test_xmss_kat` | KAT cross-validation against xmss-reference |
| `test_bds` | BDS state with bds_k=2 and bds_k=4 |
| `test_bds_serial` | BDS state serialisation round-trip |
| `test_xmss_mt_params` | All 32 XMSS-MT OIDs |
| `test_xmss_mt` | XMSS-MT keygen/sign/verify, tree-boundary crossing |
| `test_utils_internal` | ct_memcmp, ull_to_bytes, xmss_memzero, etc. |
| `test_xmss_mt_kat` | XMSS-MT KAT cross-validation |

## Step 2 — Run the analysis

```bash
isa/scripts/analyse.sh [BINARIES_DIR]
```

`BINARIES_DIR` defaults to `isa/binaries/` (relative to the script location),
so from the repo root you can simply run:

```bash
isa/scripts/analyse.sh
```

The script requires `riscv64-linux-gnu-objdump`.  Install it with:

```bash
sudo apt install binutils-riscv64-linux-gnu
```

## Step 3 — Read the report

The report is written to `isa/reports/xmss_rv64_isa_profile.md`.

### What the report contains

**Per-binary summary table**: total instruction references and unique
mnemonic count for each binary.  Binaries with many unique mnemonics exercise
more diverse code paths.

**Extension summary table**: instruction reference counts grouped by RISC-V
ISA extension.  The extensions are:

| Extension | Description |
|-----------|-------------|
| `RV64I`   | Base 64-bit integer: loads, stores, branches, arithmetic, shifts |
| `M`       | Integer multiply and divide |
| `A`       | Atomic memory operations (lr/sc, amo*) |
| `F`       | Single-precision floating-point (unexpected — XMSS is integer-only) |
| `D`       | Double-precision floating-point (unexpected) |
| `C`       | Compressed 16-bit instruction encoding |
| `Zb`      | Bit-manipulation: Zba (address gen), Zbb (rotate/clz/rev8), Zbc (clmul), Zbs (bit ops) |
| `Zicsr`   | CSR read/write instructions |
| `Zifencei`| Instruction-fetch fence |
| `OTHER`   | Unclassified mnemonics (investigate manually) |

**Per-extension detail tables**: every distinct mnemonic in each extension,
sorted by frequency.  High-frequency mnemonics are the most important to
support in Jasmin.

**Jasmin implications section**: a summary of which extensions the Jasmin
port must target, with recommendations for optimisation (e.g. using Zbb for
SHA-2 rotations).

### Interpreting instruction counts

The counts are summed across all binaries: if a routine appears in multiple
linked test binaries it is counted multiple times.  This inflates totals
but correctly reflects which instructions appear in the compiled output.

Instructions from libc (e.g. `printf`, `memcpy`) will be included because
the test binaries are dynamically linked.  To isolate pure XMSS instructions,
pass only the `libxmss.a` archive to `objdump`, or use
`riscv64-linux-gnu-objdump -d --disassemble=<symbol>` to look at specific
functions.

### Key result to look for

The Zb (bit-manipulation) section is the most interesting: `rv64gc` does not
include Zb, so the C compiler will not emit Zb instructions.  If Zb
instructions appear, it means the toolchain is using an extended march.
If they are absent (as expected), the Jasmin port can choose to use Zbb
instructions (e.g. `ror`, `rev8`, `clz`) explicitly for hash functions,
enabling optimisation beyond what the C compiler produces.

## Notes

- The binaries are not committed to the repository (they are binary build
  artefacts).  The `binaries/` directory contains only a `.gitkeep`
  placeholder.
- The toolchain used is `riscv64-linux-gnu-gcc` from the Debian/Ubuntu
  `gcc-riscv64-linux-gnu` package.  The compile flags are in
  `impl/c/cmake/toolchain-riscv64.cmake`.
- The analysis script uses only POSIX tools (`awk`, `find`, `sort`) plus
  `riscv64-linux-gnu-objdump`.  It does not execute the binaries.
