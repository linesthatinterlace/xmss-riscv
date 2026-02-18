# Repo Reorganization Plan

## Goal

Move the C implementation out of the repo root into a subdirectory so that future implementations (Jasmin, Rust, etc.) can live alongside it as peers.

## Proposed Directory Structure

```
xmss-jasmin/
├── CLAUDE.md                   # Project-level: orientation + routing for agents
├── README.md                   # Project-level: overview for humans
├── .gitignore                  # Updated for new build dir locations
├── .gitmodules                 # Unchanged
├── doc/
│   └── rfc8391.txt             # Stays at root (shared across impls)
├── third_party/
│   └── xmss-reference/         # Stays at root (shared reference)
└── impl/
    └── c/
        ├── CLAUDE.md           # NEW: C-specific agent context (architecture, rules, tests)
        ├── CMakeLists.txt      # Moved (no path changes needed)
        ├── Makefile            # Moved (unchanged — co-located with CMakeLists.txt)
        ├── README.md           # NEW: C-specific build/API/errata docs
        ├── cmake/
        │   └── toolchain-riscv64.cmake
        ├── include/xmss/
        │   ├── xmss.h
        │   ├── params.h
        │   └── types.h
        ├── src/
        │   ├── hash/
        │   │   ├── hash_iface.h
        │   │   ├── xmss_hash.c
        │   │   ├── sha2_local.c / .h
        │   │   └── shake_local.c / .h
        │   ├── params.c / .h
        │   ├── address.c / .h
        │   ├── utils.c / .h
        │   ├── wots.c / .h
        │   ├── ltree.c / .h
        │   ├── treehash.c / .h
        │   ├── bds.c / .h
        │   ├── bds_serialize.c
        │   ├── xmss.c
        │   ├── xmss_mt.c
        │   └── sk_offsets.h
        └── test/
            ├── CMakeLists.txt
            ├── test_utils.h
            └── test_*.c         # All 11 test files
```

Future implementations would be added as `impl/jasmin/`, `impl/rust/`, etc., each with their own CLAUDE.md and README.md.

## Rationale

- **`impl/` prefix**: Makes intent clear ("these are implementations of the same spec"), scales cleanly to N languages, and avoids confusing a bare `c/` directory with something else.
- **`doc/` and `third_party/` stay at root**: The RFC and reference implementation are shared resources used by all implementations, not C-specific.
- **No top-level Makefile**: Each implementation owns its own build system. With multiple implementations, a global Makefile that picks a default or grows per-impl targets would be confusing. Users `cd impl/c && make` — clear and unsurprising.
- **Per-implementation README**: Each `impl/X/` has its own README with build instructions, API docs, and implementation-specific details. The top-level README is a project overview with pointers into each implementation.
- **Per-implementation CLAUDE.md**: Each `impl/X/` has its own CLAUDE.md with architecture details, coding rules, file descriptions, build commands, and test structure. The top-level CLAUDE.md is a dispatcher that orients agents and routes them to the right implementation's context.

## CLAUDE.md split

### Top-level `CLAUDE.md` — agent dispatcher

Purpose: orient any agent landing in the repo, regardless of which implementation they're working on. Contents:

1. **What this repo is**: Multi-implementation XMSS/XMSS-MT project (one-liner).
2. **Implementation routing table**: Explicit instructions like:
   - "If you are working on the C implementation, read `impl/c/CLAUDE.md` for build commands, architecture, and coding rules."
   - "If you are working on Jasmin, read `impl/jasmin/CLAUDE.md`."
   - etc.
3. **Shared resources**: What lives at the root and why — `doc/rfc8391.txt` (the spec), `third_party/xmss-reference/` (read-only algorithmic reference).
4. **Cross-cutting rules**: Things that apply to ALL implementations regardless of language:
   - Do NOT copy code from `third_party/xmss-reference/` — use it only as an algorithmic reference, then reimplement.
   - All implementations target RFC 8391 (including Errata 7900).
   - Constant-time requirements for secret-dependent operations.
5. **Future work**: Project-level items (remaining-signatures query, XMSS-MT KAT, etc.).

### `impl/c/CLAUDE.md` — C implementation context

Purpose: everything an agent needs to work on the C code. This is essentially the current CLAUDE.md with paths made relative to `impl/c/`. Contents:

1. **Build commands**: `make`, `make test`, `make test-fast`, `make debug`, `make rv`, direct test binary paths.
2. **Architecture**: Hash abstraction boundary, no-malloc policy, key constants, ADRS structure, SK/PK layout, `xmss_PRF_idx`.
3. **Jasmin portability rules (J1–J8)**: These are enforced constraints on the C code specifically.
4. **Test structure**: All test binaries, what they test, fast vs. slow labels.
5. **Dependencies**: CMake >= 3.16, C99 compiler, no runtime deps.

All file paths in this document are relative to `impl/c/` (e.g., `src/hash/xmss_hash.c`, not `impl/c/src/hash/xmss_hash.c`) since the agent will be working within that subtree.

## Step-by-step Changes

### Step 1: Create directory and move files

Use `git mv` so history is preserved:

```
mkdir -p impl/c
git mv src/ impl/c/src/
git mv include/ impl/c/include/
git mv test/ impl/c/test/
git mv cmake/ impl/c/cmake/
git mv CMakeLists.txt impl/c/CMakeLists.txt
git mv Makefile impl/c/Makefile
```

### Step 2: Verify `impl/c/Makefile` needs no changes

The Makefile content is unchanged from the original — since it's now co-located with CMakeLists.txt, all the relative paths still work. Build directories (`build-rel/` etc.) will now appear under `impl/c/` rather than the repo root.

### Step 3: Verify `impl/c/CMakeLists.txt` and `impl/c/test/CMakeLists.txt` need no changes

All paths use `${CMAKE_SOURCE_DIR}` which will resolve to `impl/c/` whether CMake is invoked from there directly or via `-S impl/c`. No changes needed.

### Step 4: Update `.gitignore`

Update to account for build dirs now living under `impl/c/` (and future impl dirs):

```gitignore
# Build directories (per-implementation)
**/build/
**/build-rel/
**/build-rv/

# Build artefacts
*.o
*.a
CMakeCache.txt
CMakeFiles/
cmake_install.cmake
CTestTestfile.cmake
```

Using `**/` patterns so they match build dirs in any implementation subdirectory.

### Step 5: Create `impl/c/README.md`

Move the C-specific content from the current top-level README into this file:

- Building section (make targets, CMake direct invocation, RISC-V cross-compile)
- Parameter set tables (all 12 XMSS + 32 XMSS-MT)
- API usage examples (XMSS and XMSS-MT)
- Directory structure (relative to `impl/c/`)
- Jasmin portability rules table
- Errata note
- Licence

### Step 6: Rewrite top-level `README.md`

Slim it down to a project overview:

- What XMSS/XMSS-MT is (brief)
- Project goals: multi-implementation (C reference complete, Jasmin RISC-V planned, room for others)
- AI-generated disclaimer (keep this prominent)
- Repository layout overview pointing to `impl/c/`, `doc/`, `third_party/`
- Links to each implementation's README
- Licence

### Step 7: Create `impl/c/CLAUDE.md`

Move all C-specific content from the current top-level CLAUDE.md here. Keep file paths relative to `impl/c/` (not the repo root) since agents working on C will be operating in that subtree. Contents as described in the "CLAUDE.md split" section above.

### Step 8: Rewrite top-level `CLAUDE.md`

Replace with the agent dispatcher document described in the "CLAUDE.md split" section above. Key design principle: an agent should be able to read this file and immediately know which implementation-specific CLAUDE.md to read next.

### Step 9: Verify the build

After all moves and edits:

```bash
cd impl/c && make clean && make test-fast
```

## What does NOT change

- The C source code itself (no code changes, only moves)
- CMakeLists.txt internal paths (CMAKE_SOURCE_DIR resolves correctly)
- Makefile content (it moves but stays co-located with CMakeLists.txt)
- Public API headers (still `#include <xmss/xmss.h>`)
- `.gitmodules` (third_party stays put)
- `doc/` directory location

## What DOES change (user-visible)

- Build commands now require `cd impl/c` first (or `make -C impl/c`)
- Build directories appear under `impl/c/` instead of repo root
- Test binaries at `impl/c/build-rel/test/test_*` instead of `build-rel/test/test_*`
