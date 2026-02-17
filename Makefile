# Top-level wrapper around CMake.
# The real build logic lives in CMakeLists.txt; this just provides
# short commands for common operations.

BUILD     := build-rel
BUILD_DBG := build
BUILD_RV  := build-rv

.PHONY: all debug test test-fast clean rv

# Default: Release build
all:
	cmake -B $(BUILD) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD)

# Debug build (with ASan + UBSan — very slow for crypto tests)
debug:
	cmake -B $(BUILD_DBG) -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(BUILD_DBG)

# Build + run all tests (Release)
test: all
	ctest --test-dir $(BUILD) --output-on-failure

# Build + run only fast tests (no tree operations)
test-fast: all
	ctest --test-dir $(BUILD) --output-on-failure -E '(test_xmss|test_kat|test_bds)'

# RISC-V cross-compile
rv:
	cmake -B $(BUILD_RV) -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-riscv64.cmake -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_RV)

# Remove all build directories
clean:
	rm -rf $(BUILD) $(BUILD_DBG) $(BUILD_RV)
