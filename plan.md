# Repo Reorganization Plan

## Goal

Move the C implementation out of the repo root into a subdirectory so that future implementations (Jasmin, Rust, etc.) can live alongside it as peers.

## Proposed Directory Structure

```
xmss-jasmin/
├── CLAUDE.md                   # Updated for new paths
├── README.md                   # Updated: project overview, not C-specific
├── Makefile                    # Top-level: delegates to impl/c/
├── .gitignore                  # Updated for new build dir locations
├── .gitmodules                 # Unchanged
├── doc/
│   └── rfc8391.txt             # Stays at root (shared across impls)
├── third_party/
│   └── xmss-reference/         # Stays at root (shared reference)
└── impl/
    └── c/
        ├── CMakeLists.txt      # Moved + updated paths
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
- **Top-level `Makefile` delegates**: Preserves the existing `make` / `make test` workflow — users don't need to `cd impl/c`. The Makefile simply passes through to the C build system.

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
```

### Step 2: Update `impl/c/CMakeLists.txt`

The root CMakeLists.txt moves to `impl/c/`. Paths that used `${CMAKE_SOURCE_DIR}` will now resolve to `impl/c/` when built from there. Key changes:

- Source file paths (`src/params.c` etc.) → unchanged (they're relative and still correct within `impl/c/`)
- `target_include_directories`: `${CMAKE_SOURCE_DIR}/include` etc. remain correct since `CMAKE_SOURCE_DIR` will be `impl/c/` when invoked from the top-level Makefile with `cmake -B ... -S impl/c`
- `add_subdirectory(test)` → unchanged (relative path still valid)

No path changes needed inside this file since all paths are relative to `CMAKE_SOURCE_DIR` which will correctly point to `impl/c/`.

### Step 3: Update `impl/c/test/CMakeLists.txt`

Same logic — `${CMAKE_SOURCE_DIR}` will resolve to `impl/c/` so paths like `${CMAKE_SOURCE_DIR}/include`, `${CMAKE_SOURCE_DIR}/src`, `${CMAKE_SOURCE_DIR}/src/hash` remain correct. **No changes needed.**

### Step 4: Update top-level `Makefile`

Rewrite to delegate to the C implementation under `impl/c/`:

```makefile
BUILD     := build-rel
BUILD_DBG := build
BUILD_RV  := build-rv

.PHONY: all debug test test-fast clean rv help

all:
	cmake -B $(BUILD) -S impl/c -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD)

debug:
	cmake -B $(BUILD_DBG) -S impl/c -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(BUILD_DBG)

test: all
	ctest --test-dir $(BUILD) --output-on-failure

test-fast: all
	ctest --test-dir $(BUILD) --output-on-failure -L fast

rv:
	cmake -B $(BUILD_RV) -S impl/c \
	    -DCMAKE_TOOLCHAIN_FILE=impl/c/cmake/toolchain-riscv64.cmake \
	    -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_RV)

clean:
	rm -rf $(BUILD) $(BUILD_DBG) $(BUILD_RV)

help:
	@echo "Available targets:"
	@echo "  make            Release build (C implementation)"
	@echo "  make test       Build + run all tests"
	@echo "  make test-fast  Build + run fast tests only"
	@echo "  make debug      Debug build with ASan + UBSan"
	@echo "  make rv         RISC-V cross-compile"
	@echo "  make clean      Remove all build directories"
```

The key change is adding `-S impl/c` to all `cmake -B` invocations and updating the toolchain file path to `impl/c/cmake/toolchain-riscv64.cmake`.

### Step 5: Update `.gitignore`

No changes needed — `build/`, `build-rel/`, `build-rv/` are still at the repo root since build directories are placed there by the Makefile.

### Step 6: Update `README.md`

Changes needed:

1. **Introduction**: Reframe as a multi-implementation project ("implementations of XMSS/XMSS-MT"), noting C is complete and Jasmin/RISC-V is the next target.
2. **Repository structure section**: Update all paths to reflect `impl/c/` prefix. Add a note about future `impl/jasmin/`, `impl/rust/` directories.
3. **Building section**: Build commands are unchanged (`make`, `make test`, etc.) since the top-level Makefile delegates. Update the "use CMake directly" examples to show `-S impl/c`.
4. **API section**: Update `#include` paths if needed (they shouldn't change since the include dir is still `include/xmss/` relative to the build).
5. **Jasmin port section**: Update to note the planned `impl/jasmin/` location.

### Step 7: Update `CLAUDE.md`

Changes needed:

1. **Build commands section**: Update direct binary paths from `./build-rel/test/test_params` to same (build dirs stay at root). Update CMake direct-invocation examples to include `-S impl/c`.
2. **Architecture section**: Update all file path references:
   - `src/hash/xmss_hash.c` → `impl/c/src/hash/xmss_hash.c`
   - `src/hash/hash_iface.h` → `impl/c/src/hash/hash_iface.h`
   - `include/xmss/xmss.h` → `impl/c/include/xmss/xmss.h`
   - etc. for all `src/` and `include/` references
3. **Jasmin portability rules**: Clarify these apply to the C implementation (and will carry over to Jasmin).
4. **Test structure**: Update if test paths change (binary paths unchanged since build dirs are at root).
5. **Dependencies**: Note that the C impl has no deps; future impls may differ.

### Step 8: Verify the build

After all moves and edits, run `make clean && make test-fast` to verify everything still compiles and passes.

## What does NOT change

- Build directory locations (`build-rel/`, `build/`, `build-rv/` remain at repo root)
- User-facing build commands (`make`, `make test`, `make test-fast`, `make rv`, `make debug`)
- Public API headers (still `#include <xmss/xmss.h>`)
- Test binary paths (still `./build-rel/test/test_params`)
- `.gitmodules` (third_party stays put)
- The C source code itself (no code changes, only moves)
- The `doc/` directory location
