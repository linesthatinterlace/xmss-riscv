# CLAUDE.md — xmss-jasmin Jasmin implementation

Context for Claude Code when working on the Jasmin implementation of XMSS/XMSS-MT. All paths below are relative to `impl/jasmin/`.

Status: **early / in progress**.

## What Jasmin is

[Jasmin](https://github.com/jasmin-lang/jasmin) is a programming language and compiler for writing formally verified cryptographic assembly. `.jazz` source files compile to native assembly (`.s`) via `jasminc`. The formal semantics of the language enable machine-checked proofs of functional correctness and security (constant-time, etc.) in EasyCrypt.

Key properties of the language that align with our J1–J8 rules:
- No heap allocation, no VLAs, no recursion, no function pointers
- All loop bounds must be statically determined or loop-invariant parameters
- Security annotations (`#secret`, `#public`, `#msf`) for information-flow tracking
- Constant-time enforcement is a first-class concern, not an afterthought

## Target architecture

**Current target: x86-64.** The Jasmin RISC-V backend exists but is immature. We develop and verify on x86-64 first, then port once the RISC-V backend matures.

The x86-64 implementation will be tested natively. RISC-V will eventually be tested under QEMU (consistent with the C implementation).

## Toolchain

Install Jasmin via opam (recommended):

```bash
opam install jasmin
```

Or via Nix if the project adopts a Nix shell (TBD). The compiler binary is `jasminc`.

Check version:
```bash
jasminc --version
```

Formal verification (optional, later):
- **EasyCrypt** — for functional correctness and CT proofs. Installed via opam, but pinned to a dev version (the released opam package lags behind). Check the current pin before updating:
  ```bash
  opam pin list | grep easycrypt
  opam show easycrypt
  ```
  Do not run `opam upgrade easycrypt` without checking — the pin may be intentional.

## Build commands

> **Note**: Build system is not yet established. This section will be updated as it develops.

Intended workflow:

```bash
# Compile a single Jasmin source file to x86-64 assembly
jasminc -arch x86-64 src/foo.jazz -o src/foo.s

# Compile everything (once Makefile exists)
make

# Run tests (C harnesses linking against generated assembly)
make test
```

## Directory structure (planned)

```
impl/jasmin/
  CLAUDE.md
  Makefile              (to be created)
  src/
    hash/
      sha256.jazz       SHA-256 compression function
      sha512.jazz       SHA-512 compression function
      shake128.jazz     SHAKE-128 (Keccak-based)
      shake256.jazz     SHAKE-256 (Keccak-based)
    address.jazz        ADRS type and setters
    utils.jazz          ull_to_bytes, bytes_to_ull, ct_memcmp, memzero
    wots.jazz           WOTS+ sign, pkFromSig
    ltree.jazz          L-tree hash
    treehash.jazz       treehash and stack
    bds.jazz            BDS state, bds_update, bds_treehash_update
    xmss.jazz           XMSS keygen, sign, verify
    xmssmt.jazz         XMSS-MT keygen, sign, verify
  test/
    (C harnesses that link against generated .s files and call exported Jasmin functions)
  proof/
    (EasyCrypt proof files — later)
```

Hash implementations should be written from scratch in Jasmin (not auto-generated wrappers), consistent with the rest of the project.

## Jasmin language notes

### Types

```
u8, u16, u32, u64          -- unsigned integers
bool                       -- booleans (flags)
u8[N]                      -- fixed-size byte arrays (stack-allocated)
```

### Functions

```
fn foo(reg u64 x, stack u8[32] buf) -> reg u64 { ... }
```

- `reg` — lives in a register
- `stack` — lives on the stack (fixed-size array)
- `inline` — inlined at call site (like a macro; used for small helpers)
- `export` — exported with C calling convention (callable from C)

### Security annotations

```
#[secret]   // value is secret; must not be used in branches or memory addresses
#[public]   // value is public
#[msf]      // mask speculative flow (Spectre mitigation)
```

### Control flow

Only `for`, `while`, `if` — no recursion. Loop bounds must be public (not secret-dependent).

### Calling from C

`export fn` generates a C-callable symbol. The ABI follows the platform's standard (System V AMD64 for x86-64). Test harnesses in `test/` are C files that `#include` the function declarations and link against the `.s` files.

## Relationship to C implementation

The Jasmin implementation targets functional equivalence with `impl/c/`. All algorithm logic, parameter sets, SK/PK layout (Errata 7900), and domain separation constants must match exactly.

The C implementation is the **reference**: when in doubt about algorithm details, read `impl/c/src/` and `doc/rfc8391.txt`. Do not copy C code into Jasmin — reimplement from RFC + C understanding.

KAT cross-validation against `third_party/xmss-reference/` applies equally to the Jasmin implementation.

## Jasmin portability and style rules

These parallel the C implementation's J1–J8 rules:

| Rule | Requirement |
|------|-------------|
| J1 | No heap. All arrays are stack-allocated, sized by `XMSS_MAX_*` constants declared as Jasmin `param int`. |
| J2 | No function pointers. Hash dispatch is done by separate compilation (SHA-2 and SHAKE variants compiled and linked separately). |
| J3 | No recursion. All tree algorithms are iterative. |
| J4 | All loop bounds are `param int` constants or public function arguments. No secret-dependent loop counts. |
| J5 | Secret-dependent branches and memory accesses are forbidden. Use `#[secret]` annotations. CT comparison via a dedicated `ct_memcmp` function. |
| J6 | `xmss_adrs_t` is an `u32[8]` on the stack; always manipulate via setter `inline fn`s; serialise to `u8[32]` before passing to hash functions. |
| J7 | One algorithm per `.jazz` file. |
| J8 | `export fn` functions are the sole ABI boundary. Internal helpers are `fn` or `inline fn`. |

## Resources

- **Jasmin language reference for this project**: `jasmin-reference.md` (in this directory) — read this first when writing Jasmin code.
- Full language docs: https://jasmin-lang.readthedocs.io
- libjade (canonical Jasmin crypto implementations): https://github.com/formosa-crypto/libjade
  - Use the **`release/2023.05` branch** — `main` is mid-restructure and has no `.jazz` source files.
  - SHA-256: `src/crypto_hash/sha256/amd64/ref/`
  - SHAKE-256: `src/crypto_xof/shake256/amd64/ref/`
  - Keccak-f[1600]: `src/common/keccak/keccak1600/amd64/ref/`
- formosa-crypto organisation: https://github.com/formosa-crypto

## Open questions / future work

- Decide on build system (simple Makefile vs CMake integration with the rest of the project).
- Decide whether to share the CMake `XMSS_TEST_TIMEOUT_SCALE` mechanism or keep Jasmin tests independent.
- EasyCrypt proof strategy: which properties to prove first (CT? functional correctness of WOTS+?).
- RISC-V backend: track Jasmin upstream; port once backend is stable.
- Possible libjade integration or contribution.
