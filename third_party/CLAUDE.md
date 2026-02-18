# CLAUDE.md — third_party/

This directory contains third-party reference material used **only** during development.
No implementation in `impl/` depends on anything here at build time.

## xmss-reference

A git submodule tracking the upstream XMSS reference implementation.

**Status**: Read-only reference. Do NOT copy code into `impl/`.
See the top-level `CLAUDE.md` for the cross-cutting rules about its use.

### What it is used for

1. **Understanding algorithm logic** — the reference is the authoritative
   companion to RFC 8391 for understanding how WOTS+, XMSS, and XMSS-MT work.
   Read it; do not derive implementation code from it.

2. **Regenerating KAT fingerprints** — `test/gen_mt_kat.c` (our file, not part
   of the upstream reference) generates the reference fingerprints checked in
   `impl/c/test/test_xmss_mt_kat.c`.

### Compiling test/gen_mt_kat

Run from `third_party/xmss-reference/`:

```bash
gcc -Wall -O3 \
    -o test/gen_mt_kat \
    test/gen_mt_kat.c \
    params.c hash.c fips202.c hash_address.c \
    utils.c xmss_core.c xmss_commons.c wots.c randombytes.c \
    -lcrypto
```

**Key requirement**: include `randombytes.c` — the core files call `randombytes()`
and the linker will error without it even though `gen_mt_kat.c` itself uses only
`xmssmt_core_seed_keypair` (which takes an explicit seed and does not call
`randombytes` directly; it is pulled in transitively via `xmssmt_core_keypair`).

Then run:

```bash
./test/gen_mt_kat
```

Output is the `mt_vectors[]` table to paste into
`impl/c/test/test_xmss_mt_kat.c`.

### Wire OIDs used by gen_mt_kat

The reference uses wire OIDs (not our internal `0x01xxxxxx` OIDs):

| Wire OID | Parameter set |
|----------|---------------|
| 0x01 (1) | XMSSMT-SHA2_20/2_256  (n=32, h=20, d=2) |
| 0x09 (9) | XMSSMT-SHA2_20/2_512  (n=64, h=20, d=2) |
| 0x11 (17)| XMSSMT-SHAKE_20/2_256 (n=32, h=20, d=2) |
| 0x19 (25)| XMSSMT-SHAKE_20/2_512 (n=64, h=20, d=2) |

Our internal OIDs add a `0x01000000` prefix (see `impl/c/include/xmss/params.h`).

### Other reference test binaries

The upstream reference ships its own tests (wots, oid, xmss, xmssmt, …).
These are built via its own `Makefile` and are useful for spot-checking but
are not part of our test suite.

```bash
# Build the reference's own tests (from third_party/xmss-reference/)
make
```

The Makefile links `-lcrypto` (OpenSSL) for SHA-2; SHAKE is handled by
the bundled `fips202.c`.
