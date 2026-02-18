# CLAUDE.md — xmss-jasmin

Multi-implementation XMSS/XMSS-MT project (RFC 8391).

## Implementation routing

Read the CLAUDE.md in the relevant implementation directory for build commands, architecture details, and coding rules.

- **C implementation** (`impl/c/`): Complete C99 reference. See `impl/c/CLAUDE.md` for build commands, architecture, Jasmin portability rules, and test structure.
- **Rust implementation** (`impl/rust/`): Planned. See `impl/rust/CLAUDE.md` for build commands, architecture, and Rust-specific rules.
- **Jasmin implementation** (`impl/jasmin/`): In progress. Targets x86-64 first (mature backend); RISC-V port planned once the Jasmin RISC-V backend matures. See `impl/jasmin/CLAUDE.md`.

## Shared resources

- `doc/rfc8391.txt` -- the RFC 8391 specification. All implementations target this spec including Errata 7900 (SK serialisation byte layout).
- `third_party/xmss-reference/` -- git submodule of the XMSS reference C implementation. **Read-only**: used to understand algorithm logic and regenerate KAT fingerprints. **Do NOT copy code from it** -- our implementations must follow stricter rules (no VLAs, no malloc, no function pointers, etc.) which the reference violates. Only read it to understand algorithm logic, then reimplement from scratch. See `third_party/CLAUDE.md` for how to compile and run the KAT fingerprint generator.
- **formosa-xmss** (`https://github.com/formosa-crypto/formosa-xmss`) -- a human-authored Jasmin implementation of XMSS by the formosa-crypto team, subject to active research. Scope TBD. Relevant prior art for the Jasmin implementation; do not copy from it.

## CI

GitHub Actions CI runs on every push and PR:

- **`ci.yml`**: gcc and clang (native, `-Werror`), all 12 tests (~4 min each).
- **`riscv.yml`**: RISC-V cross-compile + QEMU (fast tests + sign/verify roundtrips). Weekly + manual trigger.

**Prefer pushing and letting CI run the full test suite** rather than running slow tests locally. Use `make test-fast` locally for quick smoke checks, then push to get full coverage across compilers.

Check CI status: `gh run list` / `gh run view <id>` / `gh run watch <id>`

## Cross-cutting research

### RISC-V instruction analysis

Before extending Jasmin's RISC-V backend (or contributing to it upstream), we need to understand what instructions XMSS actually requires at the ISA level. The planned approach is to disassemble the RISC-V binaries already produced by `impl/c/` and analyse which instructions appear, which ISA extensions (B for bitmanip, V for vector, etc.) are used or would help, and where gaps in Jasmin's RISC-V backend would arise.

This work draws from `impl/c/` but its output informs `impl/jasmin/`. Artifacts live in `isa/` at the project root:

- `isa/binaries/` — RISC-V ELF test binaries cross-compiled from `impl/c/` (riscv64-linux-gnu-gcc 13.3, `-march=rv64gc`)
- `isa/scripts/analyse.sh` — disassembles binaries and classifies instructions by ISA extension
- `isa/reports/xmss_rv64_isa_profile.md` — full results: XMSS is pure RV64I; Zbb (rotate/byte-swap) is absent but relevant for SHA-2 in the hash layer only
- `isa/reports/.report-todo.md` — brief for converting the profile into a PDF report for Francois Dupressoir (clean technical report style; he knows Jasmin, needs XMSS+RISC-V motivation)

See `impl/jasmin/CLAUDE.md` for how these findings affect the Jasmin port strategy.

## Cross-cutting rules

These apply to ALL implementations regardless of language:

- All implementations must target RFC 8391 including Errata 7900.
- Secret-dependent branches and memory accesses must be constant-time. Verification uses constant-time comparison. Annotate any deviations.
- No implementation should depend on `third_party/xmss-reference/` at build time -- it is a development reference only.
