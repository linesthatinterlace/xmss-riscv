# isa/ — RISC-V ISA profiling for the XMSS C implementation

This directory determines which RISC-V ISA extensions are actually used by
the XMSS C implementation. The results inform what ISA support the planned
Jasmin port must provide.

## Directory layout

```
isa/
  binaries/     Scratch space for RISC-V ELFs (not committed; see .gitignore)
  scripts/
    gen_lookup.sh     Generate mnemonic→extension lookup from riscv-opcodes
    analyse.sh        Disassemble libxmss.a and produce the ISA profile report
    mnemonic_extensions.tsv   Generated lookup table (gitignored)
  reports/
    xmss_rv64_isa_profile.md  Generated report
```

## Quick start

```bash
# 1. Build the RISC-V library
cd impl/c && make rv && cd ../..

# 2. Generate the lookup table (auto-runs if missing)
isa/scripts/gen_lookup.sh

# 3. Run the analysis (targets impl/c/build-rv/libxmss.a by default)
isa/scripts/analyse.sh
```

The report is written to `isa/reports/xmss_rv64_isa_profile.md`.

## Prerequisites

- `riscv64-linux-gnu-objdump` (from `binutils-riscv64-linux-gnu`)
- `riscv64-linux-gnu-gcc` (from `gcc-riscv64-linux-gnu`) — for building `libxmss.a`
- `third_party/riscv-opcodes` submodule initialised

```bash
sudo apt install binutils-riscv64-linux-gnu gcc-riscv64-linux-gnu
git submodule update --init third_party/riscv-opcodes
```

## Methodology

### Analysis target: `libxmss.a`

The analysis targets `libxmss.a` — the static library containing only XMSS
algorithm code (params, hash, WOTS, XMSS, XMSS-MT, BDS, utils). This isolates
XMSS from libc, `printf`, `malloc`, stack guards, and other test-harness code
that would pollute the ISA profile.

### Mnemonic classification

`gen_lookup.sh` generates an authoritative mnemonic→extension lookup table
from the `riscv-opcodes` submodule (`third_party/riscv-opcodes/`). This is
the same database used by the RISC-V toolchain to define instruction encodings.

The lookup covers:
- Real instructions (first word of non-comment, non-directive lines)
- Pseudo-ops (`$pseudo_op` lines — e.g. `mv`, `ret`, `sext.w`, `zext.b`)
- De-aliased C extension mnemonics (since objdump renders `sd` not `c.sd`)
- Manual supplement for objdump-specific pseudos not in riscv-opcodes
  (`li`, `la`, `not`, `negw`, `j`, `jr`, `call`, `tail`, etc.)

### C (compressed) encoding detection

GNU objdump renders compressed instructions using their uncompressed aliases
(`sd` not `c.sd`, `li` not `c.li`). The previous analysis looked for `c.`
prefixes that never appeared, reporting C=0.

The new analysis detects C encoding from raw instruction byte width:
- 2 bytes (4 hex chars) = 16-bit compressed
- 4 bytes (8 hex chars) = 32-bit standard

### Two orthogonal axes

1. **Semantic extension**: What the instruction does (I, M, Zba, Zbb, etc.)
   — determined by the lookup table.
2. **Encoding**: Whether it uses compressed (16-bit) or standard (32-bit)
   encoding — determined by byte width.

The semantic extension is what matters for the Jasmin port. C encoding is a
secondary observation (the assembler handles it automatically).

## Report contents

- **Methodology** section explaining what was analysed and how
- **Per-object-file summary**: instruction count, unique mnemonics, C% per `.o`
- **Semantic extension summary**: which ISA extensions are used
- **Per-extension mnemonic detail**: every mnemonic per extension with counts
  and which object files use it
- **C encoding statistics**: overall and per-object-file
- **Per-object extension breakdown**: which extensions each `.o` file uses
- **Jasmin implications**: recommended target ISA for the Jasmin port

## Key results

- XMSS (`libxmss.a`) uses only **I** and **M** extensions
- M is used only for compiler-generated address arithmetic (`mulw`, `mul`, `divuw`)
- 48% of instructions use C (compressed) encoding
- No A, F, D, Zb*, or Zicsr instructions appear
- Zbb (`ror`, `rev8`) is absent but relevant for SHA-2 — the Jasmin port
  can use it explicitly in the hash layer
