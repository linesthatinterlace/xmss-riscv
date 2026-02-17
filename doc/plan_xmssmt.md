# Plan: XMSS-MT (Multi-Tree) Implementation

## Prerequisites

- BDS serialization (doc/plan_bds_serialization.md) must be completed first.
  XMSS-MT needs to save/restore BDS states when switching between trees.

## Overview

XMSS-MT (RFC 8391 §4.2) organises `d` layers of XMSS trees into a hypertree.
Each layer has tree height `h/d`. The bottom layer (0) signs messages; each
upper layer signs the root of a tree in the layer below. Total signing
capacity is `2^h` messages.

The reference implementation uses `2*d - 1` BDS states: `d` "current" tree
states + `d-1` "next" tree states (pre-computed for the upcoming tree
transition at each layer above 0). We will follow this approach.

## Key design decisions

### 1. BDS state management: `2*d - 1` states

Following xmss-reference's approach:
- `states[0..d-1]`: current tree BDS state for each layer
- `states[d..2*d-2]`: "next" tree BDS state for layers 1..d-1
  (layer 0 doesn't need a "next" since we just reinit it)

When a tree boundary is crossed at layer `j`, the "next" state for layer `j`
becomes the "current" state (swap), and a new "next" state starts being
built for the tree after that.

### 2. State sizing

For Jasmin compatibility (J1/J3: no VLAs, no malloc), the state array must
be statically sized. Define:

```c
#define XMSS_MAX_D 12U  /* max layers (XMSSMT-*_60/12_*) */

typedef struct xmssmt_state {
    xmss_bds_state bds[2 * XMSS_MAX_D - 1];
    /* Cached WOTS signatures of lower-layer roots for upper layers.
     * When a tree boundary is crossed, we need the WOTS sig of the
     * old root signed by the parent. d-1 cached sigs. */
    uint8_t wots_sigs[(XMSS_MAX_D - 1)][XMSS_MAX_WOTS_LEN * XMSS_MAX_N];
} xmssmt_state;
```

This is large (~780 KB for MAX sizing). Callers allocate it; no malloc
in the library. For typical use (d=2..4), most of the array is unused
but the static sizing satisfies J1.

**Alternative**: If ~780 KB is too much, we could parameterise with a
smaller `XMSS_MAX_D` (e.g., 4) and only support a subset of parameter
sets. This is a tradeoff to discuss. The reference uses VLAs and malloc,
which we can't.

### 3. SK_MT format

The RFC does not define an SK format. We store:

```
SK_MT: OID(4) | idx(idx_bytes) | SK_SEED(n) | SK_PRF(n) | root(n) | SEED(n)
```

This is identical in structure to single-tree XMSS SK, just with
`idx_bytes = ceil(h/8)` instead of 4. The `xmssmt_state` is separate
(same pattern as single-tree BDS). The WOTS keys are derived
pseudorandomly from SK_SEED via PRF_keygen (no stored per-tree keys).

### 4. PK_MT format

```
PK_MT: OID(4) | root(n) | SEED(n)
```

Identical structure to XMSS PK. Same `pk_bytes`.

## Implementation steps

### Step 1: Parameter support (params.h, params.c)

Add 32 XMSS-MT OID defines to `params.h`:
```c
#define OID_XMSSMT_SHA2_20_2_256    0x01000001U
#define OID_XMSSMT_SHA2_20_4_256    0x01000002U
...
#define OID_XMSSMT_SHAKE_60_12_512  0x01000020U
```

**OID encoding note**: The RFC defines XMSS-MT OIDs 0x00000001-0x00000020
in a *separate* IANA registry from XMSS OIDs 0x00000001-0x0000000C.
Since we have a single OID table, we need to disambiguate. Options:
- Use a high bit (e.g., 0x01000000 prefix) as internal-only encoding,
  and strip/add it during serialization to/from wire format.
- Keep separate lookup functions for XMSS vs XMSS-MT.

Recommendation: Use the 0x01000000 prefix internally. Add
`xmssmt_params_from_oid()` that accepts RFC OIDs (0x00000001-0x00000020)
and maps to our internal encoding. The serialized PK/SK/sig use RFC OIDs.

Extend `oid_entry_t` to include `d`:
```c
typedef struct {
    uint32_t oid;
    const char *name;
    uint8_t  func;
    uint32_t n;
    uint32_t w;
    uint32_t h;
    uint32_t d;    /* NEW: 1 for XMSS, >1 for XMSS-MT */
} oid_entry_t;
```

Update `derive_params()`:
- `d` is set from the table (not hardcoded to 1)
- `idx_bytes = ceil(h/8)` when `d > 1` (already handled)
- `sig_bytes = idx_bytes + n + d * (h/d + len) * n` for XMSS-MT
  (d reduced sigs, each with h/d auth nodes and len WOTS chains)
- `sk_bytes` stays the same structure (OID + idx + seeds + root)
- Add `tree_height = h / d` field to `xmss_params`

Also increase `XMSS_MAX_H` from 20 to 60 if we want to support h=60
parameter sets. This significantly increases `xmss_bds_state` size.
**Alternatively**, only support h=20 and h=40 sets initially (max
tree_height = h/d = 20, so XMSS_MAX_H stays 20). h=60 sets can be
deferred.

**Recommendation**: Keep `XMSS_MAX_H = 20` (per-tree height). Add
`XMSS_MAX_FULL_H = 60` for index sizing. The BDS state is sized by
per-tree height, not full height.

Wait — `xmss_bds_state` arrays are sized by `XMSS_MAX_H` which is
the per-tree height. For XMSS-MT with h=60, d=3, per-tree height
is 20. So `XMSS_MAX_H = 20` already works! We just need to ensure
`xmss_params.h` refers to tree height for BDS, and full height for
idx_bytes/idx_max.

Changes to `xmss_params`:
```c
uint32_t h;            /* full tree height (h for XMSS, h_total for XMSS-MT) */
uint32_t tree_height;  /* per-tree height: h for XMSS (d=1), h/d for XMSS-MT */
```

BDS code uses `p->tree_height` instead of `p->h`. Single-tree XMSS:
`tree_height == h`. This is the most important refactor — **every use
of `p->h` in BDS/treehash/signing code must be audited** to determine
whether it means full height or per-tree height.

### Step 2: Refactor `p->h` → `p->tree_height` in BDS code

Before adding XMSS-MT, refactor existing code to use `tree_height`:

- `src/bds.c`: all references to `p->h` become `p->tree_height`
- `src/treehash.c`: `treehash()` and `compute_root()` use `p->tree_height`
  for loop bounds (they operate on a single tree)
- `src/xmss.c`: `xmss_sign()` auth path copy uses `p->tree_height`;
  `xmss_verify()` root computation uses `p->tree_height`
- `src/ltree.c`: does not use `p->h` (uses `p->len`), no change

For single-tree XMSS (`d=1`), `tree_height == h`, so this is a no-op
functionally. All existing tests must still pass unchanged.

**This step can be verified with `make test` before proceeding.**

### Step 3: New file `src/xmssmt.c` (J8)

Implements:

#### `xmssmt_keygen()` — based on Algorithm 15

```c
int xmssmt_keygen(const xmss_params *p, uint8_t *pk, uint8_t *sk,
                  xmssmt_state *state, uint32_t bds_k,
                  xmss_randombytes_fn randombytes);
```

Logic:
1. Sample SK_SEED, SK_PRF, SEED (3n random bytes)
2. For each layer j = 0..d-1, for the initial tree (tree_idx=0):
   - Set ADRS layer=j, tree=0
   - Run `bds_treehash_init()` to build tree and capture BDS state
     into `state->bds[j]`
   - For j < d-1: the root of layer j becomes the "message" signed
     by layer j+1
3. The root of layer d-1 is the public root
4. Initialise "next" BDS states (state->bds[d..2d-2]) for tree_idx=1
   at layers 1..d-1
5. Serialise PK and SK

**Key subtlety**: Each tree's leaves use PRF_keygen with the layer/tree
address. The existing `gen_leaf()` in bds.c already uses the ADRS
passed in, so setting layer/tree correctly is sufficient.

**For the top layer** (d-1): there is only one tree, so no "next" state
is needed. Actually — there IS a next state for layers 1..d-1 where
tree transitions can occur. Layer d-1 has `2^(h - (d-1)*(h/d))` =
`2^(h/d)` trees... wait, no. Layer d-1 has exactly 1 tree (the top).
Layer j has `2^((d-1-j) * h/d)` trees. So "next" states are only
needed for layers 0..d-2 where there's more than one tree.

Reference uses `2*d-1` states: d current + d-1 next. The "next" at
index `d+j` corresponds to layer `j+1` (for j=0..d-2). Actually,
looking at the reference more carefully, `states[d+i]` is the next
state for layer `i` (for i=0..d-2). The top layer (d-1) has only
one tree so no next state.

Wait, the reference allocates `2*d-1` states but `states[d]` is
for the "next" of layer 0. Let me re-examine...

From xmss-reference `xmss_core_fast.c`:
- `states[0..d-1]` = current BDS states for layers 0..d-1
- `states[d..2d-2]` = next BDS states
- `states[d]` is updated with `bds_state_update` for the next tree
  at layer 0 (the most frequently transitioning layer)
- When a tree boundary is crossed at layer i, states are swapped

This can be simplified for our implementation. The key insight is:
layer 0 transitions every `2^(h/d)` signatures, layer 1 transitions
every `2^(2*h/d)` signatures, etc.

#### `xmssmt_sign()` — based on Algorithm 16

```c
int xmssmt_sign(const xmss_params *p, uint8_t *sig,
                const uint8_t *msg, size_t msglen,
                uint8_t *sk, xmssmt_state *state, uint32_t bds_k);
```

Logic:
1. Read idx_sig from SK, increment
2. Compute r = PRF(SK_PRF, toByte(idx_sig, 32)) — same as single-tree
3. Compute M' = H_msg(r || root || toByte(idx_sig, n), M)
4. Split idx_sig into idx_tree (upper bits) and idx_leaf (lower h/d bits)
5. **Layer 0**: sign M' using current BDS state
   - WOTS sign + copy auth from state->bds[0]
   - Advance BDS state (bds_round + treehash_update)
6. **Layers 1..d-1**: for each layer j:
   - Compute root of layer j-1's current tree (via treehash with BDS)
   - Re-split: idx_leaf = lower h/d bits of idx_tree,
     idx_tree = remaining upper bits
   - Sign root using state->bds[j]
   - Advance BDS state
7. Handle tree transitions: when idx_leaf wraps to 0 at layer j,
   swap current/next BDS states, start building new next state
8. Distribute treehash updates across layers (budget: (h-k)/2 total
   per signature, shared across layers)

**Tree root computation for upper layers**: Algorithm 16 calls
`treeHash(SK, 0, h/d, ADRS)` which recomputes the full tree from
scratch. This is expensive (O(2^(h/d))). The reference avoids this
by caching the root — it's `state->bds[j-1].stack[0]` after the
tree is fully built, or can be derived from the top of the treehash.
Actually, the WOTS signature of the lower tree's root is computed
when the tree boundary is crossed and cached in `wots_sigs`.

This is the trickiest part. Study the reference's approach in
`xmss_core_fast.c` lines 890-980 carefully.

#### `xmssmt_verify()` — based on Algorithm 17

```c
int xmssmt_verify(const xmss_params *p,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *sig, const uint8_t *pk);
```

Logic (stateless — no BDS needed):
1. Extract idx_sig from sig
2. Compute M' = H_msg(r || root || toByte(idx_sig, n), M)
3. Split idx into idx_tree, idx_leaf
4. For layer 0: XMSS_rootFromSig (existing `compute_root` logic:
   wots_pk_from_sig → l_tree → walk auth path)
5. For layers 1..d-1: repeat with the computed root as input
6. Compare final root to PK root (ct_memcmp)

This is the simplest function — it's just d iterations of the
existing single-tree verify logic. No BDS state involved.

**Signature parsing**: Each reduced sig within Sig_MT has:
```
sig_ots (len * n bytes) | auth (tree_height * n bytes)
```
The global sig layout is:
```
idx_sig (idx_bytes) | r (n) | reduced_sig_0 | reduced_sig_1 | ... | reduced_sig_{d-1}
```
Each reduced_sig is `(len + tree_height) * n` bytes.

### Step 4: Declarations in `include/xmss/xmss.h`

Add `xmssmt_state` type and three function declarations.

### Step 5: Tests

#### `test/test_xmssmt_params.c`
- Validate all 32 XMSS-MT OIDs: n, w, h, d, tree_height, len,
  sig_bytes, pk_bytes, sk_bytes, idx_bytes

#### `test/test_xmssmt.c`
- Use the smallest practical parameter set: XMSSMT-SHA2_20/2_256
  (h=20, d=2, tree_height=10). This has 2^20 = 1M leaves but
  keygen only builds 2 trees of height 10, which is feasible.
- Keygen → sign → verify roundtrip
- Sign 5 messages, verify all (exercises BDS advancement)
- Bit-flip rejection, wrong message rejection
- **Tree boundary crossing**: sign 2^(h/d) = 1024 messages to cross
  the first tree boundary. This is the critical test. Verify signature
  1023 (last in tree 0) and signature 1024 (first in tree 1) both pass.
  This test takes ~100s in Release (1024 signs of h=10 trees).

#### `test/test_xmssmt_kat.c` (optional, deferred)
- Cross-validate against xmss-reference for XMSSMT parameter sets.
  Harder to set up because the reference's SK format differs significantly.
  Defer until the basic tests pass.

### Step 6: Build and documentation

- Add to CMakeLists.txt: `src/xmssmt.c`, test binaries
- Update CLAUDE.md: new API, test table, known limitations
- Update Makefile test-fast: add `test_xmssmt_params`, exclude
  `test_xmssmt` (too slow for fast tests)

## File summary

| File | Change |
|------|--------|
| `include/xmss/params.h` | Add XMSS-MT OIDs, `XMSS_MAX_D`, `XMSS_MAX_FULL_H` |
| `include/xmss/xmss.h` | Add `xmssmt_state`, keygen/sign/verify declarations |
| `src/params.c` | Add 32 OID entries, `d` in table, update `derive_params()`, add `tree_height` |
| `src/bds.c` | Change `p->h` → `p->tree_height` throughout |
| `src/treehash.c` | Change `p->h` → `p->tree_height` throughout |
| `src/xmss.c` | Change `p->h` → `p->tree_height` in sign/verify |
| `src/xmssmt.c` | **New file** — keygen, sign, verify |
| `test/test_xmssmt_params.c` | **New file** — parameter validation |
| `test/test_xmssmt.c` | **New file** — integration tests |
| `CMakeLists.txt` | Add sources and test binaries |
| `CLAUDE.md` | Update documentation |

## Risk areas

1. **`p->h` vs `p->tree_height` audit**: Every use of `p->h` in existing
   code must be checked. Some contexts mean "full height" (idx_max, idx_bytes,
   sig_bytes) and some mean "per-tree height" (BDS, treehash, auth path).
   Getting this wrong silently produces incorrect signatures.

2. **Tree boundary handling in sign**: The logic for swapping current/next
   BDS states and initiating new "next" tree construction is subtle. Study
   xmss-reference lines 890-980 thoroughly before implementing. The WOTS
   signature caching for cross-layer signing is the hardest part.

3. **Static sizing**: `xmssmt_state` with MAX_D=12 is ~780 KB. This may be
   acceptable for desktop/server but could be an issue for embedded targets.
   Consider whether to support all 32 parameter sets or subset.

4. **Performance**: Keygen for XMSSMT-SHA2_20/2_256 builds 2 trees of
   height 10. Each tree is ~1024 leaf computations = same as single-tree
   h=10. So keygen is ~2x single-tree. Signing is O(h/d) per sig per layer,
   so O(h) total — same as single-tree. The tree boundary crossing is the
   expensive event (rebuilds a tree).

## Verification strategy

1. After Step 2 (`tree_height` refactor): `make test` — all existing tests pass
2. After Step 3 (xmssmt.c): `make test-fast` for param tests
3. Full integration: `./build-rel/test/test_xmssmt` — roundtrip + boundary crossing
4. Final: `make test` — everything passes
