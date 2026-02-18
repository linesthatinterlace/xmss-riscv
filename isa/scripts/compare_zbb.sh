#!/usr/bin/env bash
# isa/scripts/compare_zbb.sh
#
# Build libxmss.a with both rv64gc and rv64gc_zbb, run the ISA analysis
# on each, and print a summary comparison.
#
# This reproduces the data in Tables 3-4 of the LaTeX report.
#
# Usage:
#   ./compare_zbb.sh
#
# Prerequisites:
#   - riscv64-linux-gnu-gcc (apt install gcc-riscv64-linux-gnu)
#   - riscv64-linux-gnu-objdump (apt install binutils-riscv64-linux-gnu)
#   - third_party/riscv-opcodes submodule initialised

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMPL_C="${REPO_ROOT}/impl/c"
ANALYSE="${SCRIPT_DIR}/analyse.sh"
REPORTS_DIR="${SCRIPT_DIR}/../reports"

die() { echo "ERROR: $*" >&2; exit 1; }

[[ -f "${IMPL_C}/CMakeLists.txt" ]] || die "impl/c/ not found at ${IMPL_C}"

TMPDIR_BASE="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_BASE}"' EXIT

# Common cmake args
CMAKE_COMMON=(
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-riscv64.cmake
    -DCMAKE_BUILD_TYPE=Release
)

# Build and analyse for a given march
# Usage: build_and_analyse <march> <output_md>
build_and_analyse() {
    local march="$1"
    local output="$2"
    local builddir="${TMPDIR_BASE}/build-${march}"

    echo "Building libxmss.a with -march=${march}..." >&2
    cmake -S "${IMPL_C}" -B "${builddir}" \
        "${CMAKE_COMMON[@]}" \
        -DCMAKE_C_FLAGS="-march=${march} -mabi=lp64d \
            -I/usr/riscv64-linux-gnu/include \
            -L/usr/riscv64-linux-gnu/lib" \
        > /dev/null 2>&1
    cmake --build "${builddir}" --target xmss > /dev/null 2>&1

    echo "Analysing ${builddir}/libxmss.a..." >&2
    "${ANALYSE}" "${builddir}/libxmss.a" > /dev/null 2>&1

    # Move the generated report to the requested location
    mv "${REPORTS_DIR}/xmss_rv64_isa_profile.md" "${output}"
}

# Build both variants
GC_REPORT="${TMPDIR_BASE}/rv64gc.md"
ZBB_REPORT="${TMPDIR_BASE}/rv64gc_zbb.md"

build_and_analyse "rv64gc" "${GC_REPORT}"
build_and_analyse "rv64gc_zbb" "${ZBB_REPORT}"

# Extract extension counts from the "Semantic extension summary" section only.
# The per-object-file table also has | **ext** | rows, so we must scope
# to the right section to avoid double-counting.
extract_ext() {
    local report="$1" ext="$2"
    awk -F'|' -v e="$ext" '
        /^## Semantic extension summary$/ { in_section=1; next }
        /^## / { in_section=0 }
        in_section && /^\| \*\*/ {
            gsub(/[* ]/, "", $2)
            if ($2 == e) { gsub(/[ ]/, "", $3); print $3; found=1 }
        }
        END { if (!found) print 0 }
    ' "$report"
}

extract_total() {
    local report="$1"
    awk '/^\*\*Total:.*instructions/ { print $2 }' "$report"
}

echo ""
echo "=== Extension comparison: rv64gc vs rv64gc_zbb ==="
echo ""
printf "%-12s %10s %14s %8s\n" "Extension" "rv64gc" "rv64gc_zbb" "Delta"
printf "%-12s %10s %14s %8s\n" "---------" "------" "----------" "-----"

for ext in I M Zbb; do
    gc=$(extract_ext "${GC_REPORT}" "$ext")
    zbb=$(extract_ext "${ZBB_REPORT}" "$ext")
    delta=$((zbb - gc))
    if [[ $delta -gt 0 ]]; then delta="+${delta}"; fi
    printf "%-12s %10d %14d %8s\n" "$ext" "$gc" "$zbb" "$delta"
done

gc_total=$(extract_total "${GC_REPORT}")
zbb_total=$(extract_total "${ZBB_REPORT}")
delta_total=$((zbb_total - gc_total))
printf "%-12s %10d %14d %8s\n" "Total" "$gc_total" "$zbb_total" "$delta_total"

echo ""
echo "=== Zbb instructions (rv64gc_zbb build) ==="
echo ""

# Extract the Zbb detail table (from ### Zbb to next ## heading)
awk '/^### Zbb$/{ found=1; next } found && /^##/{ exit } found{ print }' "${ZBB_REPORT}"

echo ""
echo "Done. To update the LaTeX report, manually transfer these numbers" >&2
echo "into isa/reports/xmss_rv64_isa_profile.tex (Tables 3-4)." >&2
