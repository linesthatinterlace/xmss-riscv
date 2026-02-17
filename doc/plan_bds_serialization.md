# Plan: BDS State Serialization

## Goal

Add `xmss_bds_serialize()` and `xmss_bds_deserialize()` to convert
`xmss_bds_state` to/from a flat byte buffer. This is needed for:
1. Persisting BDS state across process restarts (single-tree XMSS)
2. XMSS-MT tree switching: save/restore BDS state when moving between trees

## Design

### Serialization format

Byte-level, platform-independent (big-endian). All integers stored as
fixed-width big-endian. The format matches the field order in `xmss_bds_state`,
parameterised by `(p->n, p->h, bds_k)`.

```
Field                          Size (bytes)               Notes
-----                          -----------               -----
auth[0..h-1]                   h * n                     Auth path nodes
keep[0..h/2-1]                 (h/2) * n                 Keep nodes
stack[0..h]                    (h+1) * n                 Shared stack nodes
stack_levels[0..h]             h + 1                     1 byte each
stack_offset                   4                         uint32 big-endian
treehash[0..h-bds_k-1]:
  for each instance:
    node                       n                         Partial/completed node
    h                          4                         uint32 target height
    next_idx                   4                         uint32
    stack_usage                1                         uint8
    completed                  1                         uint8
retain[]                       retain_count * n          retain_count = max(2^bds_k - bds_k - 1, 0)
next_leaf                      4                         uint32 big-endian
```

Total serialized size is a function of `(n, h, bds_k)`. Add a helper:
```c
uint32_t xmss_bds_serialized_size(const xmss_params *p, uint32_t bds_k);
```

### API (in `include/xmss/xmss.h`)

```c
/**
 * xmss_bds_serialized_size() - Compute serialized BDS state size.
 *
 * Returns the number of bytes needed to serialize a BDS state for the
 * given parameter set and bds_k value.
 */
uint32_t xmss_bds_serialized_size(const xmss_params *p, uint32_t bds_k);

/**
 * xmss_bds_serialize() - Serialize BDS state to a byte buffer.
 *
 * @p:      Parameter set.
 * @buf:    Output buffer (xmss_bds_serialized_size() bytes).
 * @state:  BDS state to serialize.
 * @bds_k:  Retain parameter (same as used in keygen).
 *
 * Returns XMSS_OK on success.
 */
int xmss_bds_serialize(const xmss_params *p, uint8_t *buf,
                       const xmss_bds_state *state, uint32_t bds_k);

/**
 * xmss_bds_deserialize() - Deserialize BDS state from a byte buffer.
 *
 * @p:      Parameter set.
 * @state:  Output BDS state (caller-allocated).
 * @buf:    Input buffer (xmss_bds_serialized_size() bytes).
 * @bds_k:  Retain parameter (same as used in keygen).
 *
 * Returns XMSS_OK on success.
 */
int xmss_bds_deserialize(const xmss_params *p, xmss_bds_state *state,
                         const uint8_t *buf, uint32_t bds_k);
```

### Implementation file

`src/bds_serialize.c` — new file (J8: one algorithm per file).

Uses only `memcpy`, `ull_to_bytes`, `bytes_to_ull` from `utils.h`.
No hash calls, no malloc, no VLAs.

### Implementation approach

Both functions walk the same field sequence with an advancing offset pointer.

**Serialize:**
```
off = 0
for i in 0..h-1: memcpy(buf+off, state->auth[i], n); off += n
for i in 0..h/2-1: memcpy(buf+off, state->keep[i], n); off += n
for i in 0..h: memcpy(buf+off, state->stack[i], n); off += n
for i in 0..h: buf[off++] = state->stack_levels[i]
ull_to_bytes(buf+off, 4, state->stack_offset); off += 4
for i in 0..h-bds_k-1:
    memcpy(buf+off, state->treehash[i].node, n); off += n
    ull_to_bytes(buf+off, 4, state->treehash[i].h); off += 4
    ull_to_bytes(buf+off, 4, state->treehash[i].next_idx); off += 4
    buf[off++] = state->treehash[i].stack_usage
    buf[off++] = state->treehash[i].completed
retain_count = (bds_k > 0) ? (1 << bds_k) - bds_k - 1 : 0
for i in 0..retain_count-1: memcpy(buf+off, state->retain[i], n); off += n
ull_to_bytes(buf+off, 4, state->next_leaf); off += 4
assert(off == xmss_bds_serialized_size(p, bds_k))
```

**Deserialize:** mirror of serialize, reading from buf into state fields.
Zero the full `xmss_bds_state` first with memset to clear any unused
MAX-sized padding beyond the actual (h, n, bds_k) dimensions.

**Size calculation:**
```
size = h*n                        // auth
     + (h/2)*n                    // keep
     + (h+1)*n                    // stack nodes
     + (h+1)                      // stack levels
     + 4                          // stack_offset
     + (h-bds_k) * (n + 4 + 4 + 1 + 1)  // treehash instances
     + retain_count * n           // retain
     + 4                          // next_leaf
```

### Test: `test/test_bds_serial.c`

Add to CMakeLists.txt as a new test binary.

**Tests:**
1. **Round-trip after keygen**: keygen → serialize → deserialize → sign → verify.
   Confirms deserialized state produces valid signatures.
2. **Round-trip mid-signing**: keygen → sign 5 → serialize → deserialize → sign → verify.
   Confirms state is correctly captured after partial use.
3. **Byte-exact round-trip**: serialize → deserialize → re-serialize, compare
   buffers are identical.
4. **Size consistency**: verify `xmss_bds_serialized_size()` matches actual
   bytes written by serialize.
5. **Multiple parameter sets**: test with at least SHA2_10_256 (n=32, h=10)
   and SHA2_10_512 (n=64, h=10).
6. **Non-zero bds_k**: test round-trip with bds_k=2 to exercise retain serialization.

All tests should use BDS with `bds_k=0` and `bds_k=2`, deterministic RNG,
Release build. This test is fast (only 1-2 keygen + a few signs per param set).

### Build changes

- Add `src/bds_serialize.c` to `CMakeLists.txt` source list
- Add `test/test_bds_serial.c` as new test binary
- Add `test_bds_serial` to `make test-fast` since it's quick

### Files to modify

| File | Change |
|------|--------|
| `include/xmss/xmss.h` | Add 3 function declarations |
| `src/bds_serialize.c` | **New file** — serialize, deserialize, size functions |
| `test/test_bds_serial.c` | **New file** — round-trip tests |
| `CMakeLists.txt` | Add source and test binary |
| `Makefile` | Add test_bds_serial to test-fast if not auto-picked up |
| `CLAUDE.md` | Add test_bds_serial to test table |

### Reference comparison

The xmss-reference serializes BDS state into the SK itself (in
`xmss_core_fast.c:xmssmt_serialize_state`). Their format is similar —
walking the same fields — but uses VLAs and pointer-based bds_state
(we use fixed MAX-sized arrays). Our format should produce the same
field sequence for the actual-sized region, just with a clean
parameterised size function instead of embedded-in-SK layout.

### Verification

```bash
make test-fast    # includes test_bds_serial
```

Should be < 1 second. No need to run slow tests for this change.
