# CLAUDE.md — xmss-jasmin

Multi-implementation XMSS/XMSS-MT project (RFC 8391).

## Implementation routing

Read the CLAUDE.md in the relevant implementation directory for build commands, architecture details, and coding rules.

- **C implementation** (`impl/c/`): Complete C99 reference. See `impl/c/CLAUDE.md` for build commands, architecture, Jasmin portability rules, and test structure.
- **Rust implementation** (`impl/rust/`): Planned. See `impl/rust/CLAUDE.md` for build commands, architecture, and Rust-specific rules.
- **Jasmin implementation** (`impl/jasmin/`): Planned. Will target RISC-V 64-bit verified assembly.

## Shared resources

- `doc/rfc8391.txt` -- the RFC 8391 specification. All implementations target this spec including Errata 7900 (SK serialisation byte layout).
- `third_party/xmss-reference/` -- git submodule of the XMSS reference implementation. **Read-only**: used to understand algorithm logic and regenerate KAT fingerprints. **Do NOT copy code from it** -- our implementations must follow stricter rules (no VLAs, no malloc, no function pointers, etc.) which the reference violates. Only read it to understand algorithm logic, then reimplement from scratch.

## Cross-cutting rules

These apply to ALL implementations regardless of language:

- All implementations must target RFC 8391 including Errata 7900.
- Secret-dependent branches and memory accesses must be constant-time. Verification uses constant-time comparison. Annotate any deviations.
- No implementation should depend on `third_party/xmss-reference/` at build time -- it is a development reference only.
