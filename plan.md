# Repo Reorganization Plan

## Goal

Move the C implementation out of the repo root into a subdirectory so that future implementations (Jasmin, Rust, etc.) can live alongside it as peers.

## Proposed Directory Structure

```
xmss-jasmin/
├── CLAUDE.md                   # Updated for new paths
├── README.md                   # Rewritten: project overview only
├── .gitignore                  # Updated for new build dir locations
├── .gitmodules                 # Unchanged
├── doc/
│   └── rfc8391.txt             # Stays at root (shared across impls)
├── third_party/
│   └── xmss-reference/         # Stays at root (shared reference)
└── impl/
    └── c/
        ├── CMakeLists.txt      # Moved (no path changes needed)
        ├── Makefile            # Moved + updated (build dirs now relative to impl/c/)
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

Future implementations would be added as `impl/jasmin/`, `impl/rust/`, etc.

## Rationale

- **`impl/` prefix**: Makes intent clear ("these are implementations of the same spec"), scales cleanly to N languages, and avoids confusing a bare `c/` directory with something else.
- **`doc/` and `third_party/` stay at root**: The RFC and reference implementation are shared resources used by all implementations, not C-specific.
- **No top-level Makefile**: Each implementation owns its own build system. With multiple implementations, a global Makefile that picks a default or grows per-impl targets would be confusing. Users `cd impl/c && make` — clear and unsurprising.
- **Per-implementation README**: Each `impl/X/` has its own README with build instructions, API docs, and implementation-specific details. The top-level README is a project overview with pointers into each implementation.

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

### Step 2: Update `impl/c/Makefile`

The Makefile now lives inside `impl/c/`, so build directories should be relative to that location. Update all paths:

```makefile
BUILD     := build-rel
BUILD_DBG := build
BUILD_RV  := build-rv

.PHONY: all debug test test-fast clean rv help

all:
	cmake -B $(BUILD) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD)

debug:
	cmake -B $(BUILD_DBG) -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(BUILD_DBG)

test: all
	ctest --test-dir $(BUILD) --output-on-failure

test-fast: all
	ctest --test-dir $(BUILD) --output-on-failure -L fast

rv:
	cmake -B $(BUILD_RV) -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-riscv64.cmake \
	    -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_RV)

clean:
	rm -rf $(BUILD) $(BUILD_DBG) $(BUILD_RV)

help:
	@echo "Available targets:"
	@echo "  make            Release build"
	@echo "  make test       Build + run all tests"
	@echo "  make test-fast  Build + run fast tests only"
	@echo "  make debug      Debug build with ASan + UBSan"
	@echo "  make rv         RISC-V cross-compile"
	@echo "  make clean      Remove all build directories"
```

The Makefile content is actually unchanged from the original — since it's now co-located with CMakeLists.txt, all the relative paths still work. Build directories (`build-rel/` etc.) will now appear under `impl/c/` rather than the repo root.

### Step 3: Update `impl/c/CMakeLists.txt` and `impl/c/test/CMakeLists.txt`

No path changes needed inside either file. All paths use `${CMAKE_SOURCE_DIR}` which will resolve to `impl/c/` whether CMake is invoked from there directly or via `-S impl/c`.

### Step 4: Update `.gitignore`

Update to account for build dirs now living under `impl/c/`:

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
- Repository structure (relative to `impl/c/`)
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

### Step 7: Update `CLAUDE.md`

Changes needed:

1. **Build commands section**: Update paths — users now `cd impl/c` first. Direct binary paths become `./impl/c/build-rel/test/test_params` etc. RISC-V example updated similarly.
2. **Architecture section**: Update all file path references to include `impl/c/` prefix:
   - `src/hash/xmss_hash.c` → `impl/c/src/hash/xmss_hash.c`
   - `src/hash/hash_iface.h` → `impl/c/src/hash/hash_iface.h`
   - `include/xmss/xmss.h` → `impl/c/include/xmss/xmss.h`
   - etc. for all `src/` and `include/` references
3. **Jasmin portability rules**: Clarify these apply to the C implementation (and will carry over to Jasmin).
4. **Test structure**: Update binary paths to `./impl/c/build-rel/test/test_*`.
5. **Dependencies**: Note that the C impl has no deps; future impls may differ.

### Step 8: Verify the build

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
