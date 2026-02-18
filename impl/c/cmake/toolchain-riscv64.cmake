# cmake/toolchain-riscv64.cmake
# Cross-compilation toolchain for RISC-V 64-bit Linux.
#
# Usage:
#   cmake -B build-rv -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-riscv64.cmake
#   cmake --build build-rv
#   qemu-riscv64 -L /usr/riscv64-linux-gnu build-rv/test/test_xmss

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR riscv64)

# Adjust prefix if your toolchain uses a different naming convention
set(CROSS_PREFIX "riscv64-linux-gnu-")

find_program(CMAKE_C_COMPILER   "${CROSS_PREFIX}gcc")
find_program(CMAKE_CXX_COMPILER "${CROSS_PREFIX}g++")
find_program(CMAKE_AR           "${CROSS_PREFIX}ar")
find_program(CMAKE_RANLIB       "${CROSS_PREFIX}ranlib")
find_program(CMAKE_STRIP        "${CROSS_PREFIX}strip")

# On Ubuntu, the cross-libc lives directly under /usr/riscv64-linux-gnu
# which is NOT a proper sysroot hierarchy, so we don't set CMAKE_SYSROOT.
# Instead we pass the library and include paths explicitly via flags.
set(CMAKE_C_FLAGS_INIT
    "-march=rv64gc -mabi=lp64d \
     -I/usr/riscv64-linux-gnu/include \
     -L/usr/riscv64-linux-gnu/lib"
)
set(CMAKE_EXE_LINKER_FLAGS_INIT
    "-Wl,-rpath-link,/usr/riscv64-linux-gnu/lib"
)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# QEMU emulator for CTest — allows `ctest` to run cross-compiled tests.
find_program(QEMU_RISCV64 qemu-riscv64)
if(QEMU_RISCV64)
    set(CMAKE_CROSSCOMPILING_EMULATOR "${QEMU_RISCV64};-L;/usr/riscv64-linux-gnu"
        CACHE STRING "Emulator for cross-compiled test binaries")
endif()
