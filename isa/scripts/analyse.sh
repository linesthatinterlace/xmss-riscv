#!/usr/bin/env bash
# isa/scripts/analyse.sh
#
# Profile which RISC-V ISA extensions are used by the XMSS C implementation.
#
# Usage:
#   ./analyse.sh [BINARIES_DIR]
#
# BINARIES_DIR defaults to ../binaries/ relative to this script.
# Output is written to ../reports/xmss_rv64_isa_profile.md
#
# Requirements:
#   riscv64-linux-gnu-objdump  (from binutils-riscv64-linux-gnu on Debian/Ubuntu)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARIES_DIR="${1:-${SCRIPT_DIR}/../binaries}"
REPORTS_DIR="${SCRIPT_DIR}/../reports"
REPORT="${REPORTS_DIR}/xmss_rv64_isa_profile.md"
OBJDUMP="riscv64-linux-gnu-objdump"
TMPDIR_BASE="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_BASE}"' EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() { echo "ERROR: $*" >&2; exit 1; }

check_deps() {
    if ! command -v "${OBJDUMP}" >/dev/null 2>&1; then
        die "${OBJDUMP} not found. Install with: sudo apt install binutils-riscv64-linux-gnu"
    fi
    if ! command -v awk >/dev/null 2>&1; then
        die "awk not found"
    fi
}

# Emit a horizontal rule of dashes (72 chars) into the report
hr() { printf -- '---\n'; }

# ---------------------------------------------------------------------------
# ISA classification
#
# classify_mnemonic <mnemonic>  ->  prints one of:
#   RV64I | M | A | F | D | C | Zb | Zicsr | Zifencei | OTHER
#
# Rules are matched in priority order; first match wins.
# All comparisons are against the lowercase mnemonic.
# ---------------------------------------------------------------------------
classify_mnemonic() {
    local m="$1"

    # ---- Compressed (C extension) ----------------------------------------
    # All C instructions start with "c." (e.g. c.addi, c.ld, c.sw, c.jr)
    case "$m" in
        c.*)  echo "C"; return ;;
    esac

    # ---- Zicsr — CSR instructions ----------------------------------------
    case "$m" in
        csrrw|csrrs|csrrc|csrrwi|csrrsi|csrrci|csrr|csrw|csrs|csrc) echo "Zicsr"; return ;;
    esac

    # ---- Zifencei -----------------------------------------------------------
    case "$m" in
        fence.i) echo "Zifencei"; return ;;
    esac

    # ---- A extension — atomics -------------------------------------------
    # lr.w, lr.d, sc.w, sc.d, amoswap.*, amoadd.*, amoand.*, amoor.*,
    # amoxor.*, amomin.*, amomax.*, amominu.*, amomaxu.*
    case "$m" in
        lr.w|lr.d|sc.w|sc.d) echo "A"; return ;;
        amo*) echo "A"; return ;;
    esac

    # ---- M extension — multiply / divide ---------------------------------
    # mul, mulh, mulhsu, mulhu, mulw
    # div, divu, divw, divuw
    # rem, remu, remw, remuw
    case "$m" in
        mul|mulh|mulhsu|mulhu|mulw) echo "M"; return ;;
        div|divu|divw|divuw)        echo "M"; return ;;
        rem|remu|remw|remuw)        echo "M"; return ;;
    esac

    # ---- F extension — single-precision float ----------------------------
    # All start with f (fadd, fsub, fmul, fdiv, fsqrt, fmin, fmax,
    # fmadd, fmsub, fnmadd, fnmsub, fcvt, fmv, feq, flt, fle, fclass)
    # Also flw / fsw (float load/store)
    case "$m" in
        fadd.s|fsub.s|fmul.s|fdiv.s|fsqrt.s)          echo "F"; return ;;
        fmin.s|fmax.s)                                  echo "F"; return ;;
        fmadd.s|fmsub.s|fnmadd.s|fnmsub.s)             echo "F"; return ;;
        fcvt.w.s|fcvt.wu.s|fcvt.s.w|fcvt.s.wu)        echo "F"; return ;;
        fcvt.l.s|fcvt.lu.s|fcvt.s.l|fcvt.s.lu)        echo "F"; return ;;
        fmv.w.x|fmv.x.w|fmv.s)                        echo "F"; return ;;
        feq.s|flt.s|fle.s|fclass.s)                    echo "F"; return ;;
        flw|fsw)                                        echo "F"; return ;;
    esac

    # ---- D extension — double-precision float ----------------------------
    case "$m" in
        fadd.d|fsub.d|fmul.d|fdiv.d|fsqrt.d)          echo "D"; return ;;
        fmin.d|fmax.d)                                  echo "D"; return ;;
        fmadd.d|fmsub.d|fnmadd.d|fnmsub.d)             echo "D"; return ;;
        fcvt.w.d|fcvt.wu.d|fcvt.d.w|fcvt.d.wu)        echo "D"; return ;;
        fcvt.l.d|fcvt.lu.d|fcvt.d.l|fcvt.d.lu)        echo "D"; return ;;
        fcvt.s.d|fcvt.d.s)                             echo "D"; return ;;
        fmv.d.x|fmv.x.d|fmv.d)                        echo "D"; return ;;
        feq.d|flt.d|fle.d|fclass.d)                    echo "D"; return ;;
        fld|fsd)                                        echo "D"; return ;;
    esac

    # ---- Zb* — bit-manipulation extensions --------------------------------
    # Zba: sh1add, sh2add, sh3add, sh1add.uw, sh2add.uw, sh3add.uw,
    #      add.uw, slli.uw
    # Zbb: andn, orn, xnor, clz, clzw, ctz, ctzw, cpop, cpopw,
    #      max, maxu, min, minu, sext.b, sext.h, zext.h,
    #      rol, rolw, ror, rori, roriw, rorw,
    #      rev8, orc.b
    # Zbc: clmul, clmulh, clmulr
    # Zbs: bclr, bclri, bext, bexti, binv, binvi, bset, bseti
    case "$m" in
        # Zba
        sh1add|sh2add|sh3add)                           echo "Zb"; return ;;
        sh1add.uw|sh2add.uw|sh3add.uw)                 echo "Zb"; return ;;
        add.uw|slli.uw)                                 echo "Zb"; return ;;
        # Zbb
        andn|orn|xnor)                                  echo "Zb"; return ;;
        clz|clzw|ctz|ctzw|cpop|cpopw)                  echo "Zb"; return ;;
        max|maxu|min|minu)                              echo "Zb"; return ;;
        sext.b|sext.h|zext.h)                          echo "Zb"; return ;;
        rol|rolw|ror|rorw|rori|roriw)                  echo "Zb"; return ;;
        rev8|orc.b)                                     echo "Zb"; return ;;
        # Zbc
        clmul|clmulh|clmulr)                           echo "Zb"; return ;;
        # Zbs
        bclr|bclri|bext|bexti|binv|binvi|bset|bseti)  echo "Zb"; return ;;
    esac

    # ---- RV64I base integer + privileged / system -------------------------
    # Loads: lb, lh, lw, ld, lbu, lhu, lwu
    # Stores: sb, sh, sw, sd
    # Arithmetic reg: add, sub, addw, subw, and, or, xor, sll, srl, sra,
    #                 sllw, srlw, sraw
    # Arithmetic imm: addi, addiw, andi, ori, xori, slti, sltiu,
    #                 slli, srli, srai, slliw, srliw, sraiw
    # Compares: slt, sltu, slti, sltiu
    # Upper imm: lui, auipc
    # Jumps: jal, jalr
    # Branches: beq, bne, blt, bge, bltu, bgeu
    # System: ecall, ebreak, fence, mret, sret, wfi, nop, ret
    # Pseudo: mv, li, la, neg, not, seqz, snez, sltz, sgtz, beqz, bnez,
    #         bltz, bgez, bgtz, blez, j, jr, call, tail
    case "$m" in
        # Loads
        lb|lh|lw|ld|lbu|lhu|lwu)                           echo "RV64I"; return ;;
        # Stores
        sb|sh|sw|sd)                                        echo "RV64I"; return ;;
        # Register arithmetic
        add|sub|addw|subw)                                  echo "RV64I"; return ;;
        and|or|xor)                                         echo "RV64I"; return ;;
        sll|srl|sra|sllw|srlw|sraw)                        echo "RV64I"; return ;;
        # Immediate arithmetic
        addi|addiw|andi|ori|xori)                           echo "RV64I"; return ;;
        slli|srli|srai|slliw|srliw|sraiw)                  echo "RV64I"; return ;;
        # Compares
        slt|sltu|slti|sltiu)                                echo "RV64I"; return ;;
        # Upper-immediate
        lui|auipc)                                          echo "RV64I"; return ;;
        # Jumps
        jal|jalr)                                           echo "RV64I"; return ;;
        # Branches
        beq|bne|blt|bge|bltu|bgeu)                         echo "RV64I"; return ;;
        # System / fence
        ecall|ebreak|fence|fence.tso|mret|sret|uret|wfi)   echo "RV64I"; return ;;
        # Pseudo-instructions (assembler-generated from real RV64I encodings)
        nop|ret|mv|li|la|neg|not|negw)                      echo "RV64I"; return ;;
        seqz|snez|sltz|sgtz)                                echo "RV64I"; return ;;
        beqz|bnez|bltz|bgez|bgtz|blez)                     echo "RV64I"; return ;;
        j|jr|call|tail)                                     echo "RV64I"; return ;;
        # Sign/zero-extend pseudos (aliases for addiw/andi encodings)
        sext.w|zext.b|zext.h|zext.w)                       echo "RV64I"; return ;;
    esac

    # ---- Anything else ----------------------------------------------------
    echo "OTHER"
}

# ---------------------------------------------------------------------------
# Disassemble one binary; write per-mnemonic counts to a file.
# Output format (TSV): <count> <TAB> <mnemonic>
# ---------------------------------------------------------------------------
disassemble_binary() {
    local bin="$1"
    local out="$2"

    # objdump -d output: lines with actual instructions look like:
    #   <hex_addr>:  <hex_bytes>   <mnemonic>  [operands]
    # We strip the address/bytes columns and pull out the first word after
    # the tab that follows the hex bytes.  Blank lines and section headers
    # are filtered by requiring a hex address prefix.
    "${OBJDUMP}" -d --no-show-raw-insn "$bin" 2>/dev/null \
    | awk '
        # Match instruction lines: leading whitespace, hex address, colon, tab
        /^[[:space:]]+[0-9a-f]+:[[:space:]]/ {
            # Field layout after stripping address+colon:
            # $1 = "addr:"  $2 = mnemonic  (objdump --no-show-raw-insn)
            mnem = $2
            if (mnem != "" && mnem != ".") {
                count[mnem]++
            }
        }
        END {
            for (m in count) printf "%d\t%s\n", count[m], m
        }
    ' | sort -rn > "$out"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

check_deps

BINARIES_DIR="$(realpath "${BINARIES_DIR}")"
REPORTS_DIR="$(realpath "${REPORTS_DIR}")"

if [[ ! -d "${BINARIES_DIR}" ]]; then
    die "Binaries directory not found: ${BINARIES_DIR}"
fi

# Collect ELF binaries (exclude .gitkeep and any non-ELF files)
mapfile -t BINARIES < <(
    find "${BINARIES_DIR}" -maxdepth 1 -type f -not -name '.*' \
    | sort \
    | while read -r f; do
        # Check ELF magic bytes (first 4 bytes = 7f 45 4c 46)
        if [[ "$(head -c 4 "$f" 2>/dev/null | od -A n -t x1 | tr -d ' \n')" == "7f454c46" ]]; then
            echo "$f"
        fi
    done
)

if [[ ${#BINARIES[@]} -eq 0 ]]; then
    die "No RISC-V ELF binaries found in ${BINARIES_DIR}. Copy them from impl/c/build-rv/test/ first."
fi

echo "Found ${#BINARIES[@]} binary/binaries in ${BINARIES_DIR}"

mkdir -p "${REPORTS_DIR}"

# ---- Per-binary disassembly and mnemonic extraction ---------------------

# Accumulator for global counts: tmpfile maps mnemonic -> total_count
GLOBAL_COUNTS="${TMPDIR_BASE}/global_counts.tsv"
touch "${GLOBAL_COUNTS}"

# We'll also track per-binary total instruction counts for the summary table
declare -A BIN_TOTAL_INSNS
declare -A BIN_UNIQUE_MNEMS

for bin in "${BINARIES[@]}"; do
    name="$(basename "$bin")"
    per_bin="${TMPDIR_BASE}/${name}.tsv"
    echo "  Disassembling ${name}..."
    disassemble_binary "$bin" "${per_bin}"
    BIN_TOTAL_INSNS["$name"]=$(awk '{s+=$1} END{print s+0}' "${per_bin}")
    BIN_UNIQUE_MNEMS["$name"]=$(wc -l < "${per_bin}")
    # Accumulate into global
    cat "${per_bin}" >> "${GLOBAL_COUNTS}"
done

# Merge global counts: sum all occurrences of the same mnemonic
GLOBAL_MERGED="${TMPDIR_BASE}/global_merged.tsv"
sort -k2 "${GLOBAL_COUNTS}" \
| awk '{count[$2]+=$1} END{for(m in count) printf "%d\t%s\n",count[m],m}' \
| sort -rn > "${GLOBAL_MERGED}"

TOTAL_GLOBAL=$(awk '{s+=$1} END{print s+0}' "${GLOBAL_MERGED}")
UNIQUE_GLOBAL=$(wc -l < "${GLOBAL_MERGED}")

echo "  Total instruction references (summed across all binaries): ${TOTAL_GLOBAL}"

# ---- Classify every mnemonic --------------------------------------------
# Build per-extension files: each line is "<count> <TAB> <mnemonic>"
declare -A EXT_FILES
for ext in RV64I M A F D C Zb Zicsr Zifencei OTHER; do
    EXT_FILES["$ext"]="${TMPDIR_BASE}/ext_${ext}.tsv"
    touch "${EXT_FILES[$ext]}"
done

UNCLASSIFIED="${TMPDIR_BASE}/unclassified.txt"
> "${UNCLASSIFIED}"

while IFS=$'\t' read -r cnt mnem; do
    ext="$(classify_mnemonic "$mnem")"
    printf '%d\t%s\n' "$cnt" "$mnem" >> "${EXT_FILES[$ext]}"
    if [[ "$ext" == "OTHER" ]]; then
        echo "$mnem" >> "${UNCLASSIFIED}"
    fi
done < "${GLOBAL_MERGED}"

# Sort each extension file by count descending
for ext in RV64I M A F D C Zb Zicsr Zifencei OTHER; do
    sort -rn -k1 "${EXT_FILES[$ext]}" -o "${EXT_FILES[$ext]}"
done

# ---- Extension summary counts -------------------------------------------
declare -A EXT_TOTAL EXT_UNIQUE
for ext in RV64I M A F D C Zb Zicsr Zifencei OTHER; do
    EXT_TOTAL["$ext"]=$(awk '{s+=$1} END{print s+0}' "${EXT_FILES[$ext]}")
    EXT_UNIQUE["$ext"]=$(wc -l < "${EXT_FILES[$ext]}" | tr -d ' ')
done

# ---- Generate Markdown report -------------------------------------------
echo "Writing report to ${REPORT}..."

{
cat <<HEADER
# XMSS RISC-V ISA Profile

Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Toolchain: \`${OBJDUMP}\` (\`$(${OBJDUMP} --version | head -1)\`)
Binaries directory: \`${BINARIES_DIR}\`

This report profiles the RISC-V ISA extensions used across all XMSS test
binaries compiled with \`-march=rv64gc\`.  The goal is to determine what ISA
support the Jasmin port must provide.

HEADER

# --- Per-binary summary table ---
cat <<TABLE_HEADER
## Per-binary summary

| Binary | Total insn refs | Unique mnemonics |
|--------|-----------------|-----------------|
TABLE_HEADER

for bin in "${BINARIES[@]}"; do
    name="$(basename "$bin")"
    printf '| `%s` | %s | %s |\n' \
        "$name" \
        "${BIN_TOTAL_INSNS[$name]}" \
        "${BIN_UNIQUE_MNEMS[$name]}"
done

printf '\n**Total across all binaries:** %d instruction references, %d unique mnemonics\n\n' \
    "${TOTAL_GLOBAL}" "${UNIQUE_GLOBAL}"

# --- Extension summary table ---
cat <<EXT_HEADER

## Extension summary

Instruction reference counts summed across all binaries, grouped by RISC-V
ISA extension.  "Refs" counts every occurrence in every binary's disassembly
(a mnemonic appearing in a shared library pulled into multiple binaries will
be counted multiple times).  "Unique" is the number of distinct mnemonics in
that extension that appeared at least once.

| Extension | Description | Refs | Unique mnemonics | Present? |
|-----------|-------------|------|-----------------|----------|
EXT_HEADER

ext_row() {
    local ext="$1" desc="$2"
    local refs="${EXT_TOTAL[$ext]}" uniq="${EXT_UNIQUE[$ext]}"
    local flag
    if [[ "$refs" -gt 0 ]]; then flag="YES"; else flag="no"; fi
    printf '| %-9s | %-47s | %6s | %15s | %-8s |\n' \
        "$ext" "$desc" "$refs" "$uniq" "$flag"
}

ext_row "RV64I"    "Base integer (loads, stores, branches, arith)"
ext_row "M"        "Integer multiply/divide"
ext_row "A"        "Atomics (lr/sc/amo)"
ext_row "F"        "Single-precision float (unexpected for XMSS)"
ext_row "D"        "Double-precision float (unexpected for XMSS)"
ext_row "C"        "Compressed 16-bit instructions"
ext_row "Zb"       "Bit-manipulation (Zba/Zbb/Zbc/Zbs)"
ext_row "Zicsr"    "CSR read/write instructions"
ext_row "Zifencei" "Instruction-fetch fence"
ext_row "OTHER"    "Unclassified (see section below)"

echo ""

# --- Per-extension detail sections ---
detail_section() {
    local ext="$1" desc="$2" notes="$3"
    local refs="${EXT_TOTAL[$ext]}" uniq="${EXT_UNIQUE[$ext]}"
    if [[ "$refs" -eq 0 ]]; then
        printf '\n### %s — %s\n\nNot present in any binary.\n' "$ext" "$desc"
        return
    fi
    printf '\n### %s — %s\n\n%s\n\n' "$ext" "$desc" "$notes"
    printf '| Count | Mnemonic |\n'
    printf '|-------|----------|\n'
    while IFS=$'\t' read -r cnt mnem; do
        printf '| %6d | `%s` |\n' "$cnt" "$mnem"
    done < "${EXT_FILES[$ext]}"
    echo ""
}

detail_section "RV64I" "Base integer" \
    "Core integer operations. Always required."

detail_section "M" "Multiply/divide" \
    "Integer multiply/divide. Used by the C compiler for address arithmetic and loop induction; not directly needed by XMSS algorithm logic."

detail_section "A" "Atomics" \
    "Atomic memory operations. If present, likely from libc (e.g. pthread mutexes in test harness), not from XMSS algorithm code itself."

detail_section "F" "Single-precision float" \
    "UNEXPECTED. Float instructions should not appear in XMSS. If present, investigate the source — possibly a libc function or compiler-generated code."

detail_section "D" "Double-precision float" \
    "UNEXPECTED. Double-precision float should not appear in XMSS. If present, investigate (may be compiler-generated for 64-bit operations on some toolchain versions)."

detail_section "C" "Compressed" \
    "16-bit compressed encoding. Present whenever the toolchain emits C-extension code (enabled by default in rv64gc). These are just re-encodings of RV64I/M/A/F/D instructions; no new semantics. The Jasmin port does not need to explicitly emit C instructions — the assembler handles encoding."

detail_section "Zb" "Bit-manipulation (Zba/Zbb/Zbc/Zbs)" \
    "Bit-manipulation extensions. Relevant for hash function acceleration in Jasmin:
- **Zba**: address generation (sh1add, sh2add, sh3add)
- **Zbb**: rotates (rol/ror), bit-reverse (rev8), count-leading-zeros (clz/ctz), min/max
- **Zbc**: carry-less multiply (clmul) — relevant for GCM/CRC but not SHA-2/SHAKE
- **Zbs**: single-bit ops (bset/bclr/binv/bext)

If Zb instructions appear here, they were emitted by the C compiler. If absent, the compiler did not auto-vectorise to Zb; the Jasmin port could still use them explicitly for SHA-2 rotations."

detail_section "Zicsr" "CSR instructions" \
    "Control/Status Register access. If present, likely from libc startup or performance-counter access in test harness."

detail_section "Zifencei" "Instruction-fetch fence" \
    "fence.i instruction. If present, likely from libc or dynamic linker, not XMSS."

# --- OTHER / unclassified ---
printf '\n### OTHER — Unclassified mnemonics\n\n'
if [[ "${EXT_TOTAL[OTHER]}" -eq 0 ]]; then
    printf 'No unclassified mnemonics. All instructions were recognised.\n\n'
else
    printf 'The following mnemonics were not matched by the classifier. '
    printf 'They may be new extensions, vendor-specific instructions, '
    printf 'or objdump pseudo-mnemonics for this toolchain version. '
    printf 'Inspect manually.\n\n'
    printf '| Count | Mnemonic |\n'
    printf '|-------|----------|\n'
    while IFS=$'\t' read -r cnt mnem; do
        printf '| %6d | `%s` |\n' "$cnt" "$mnem"
    done < "${EXT_FILES[OTHER]}"
    echo ""
fi

# --- Jasmin implications ---
cat <<JASMIN

## Implications for the Jasmin port

Based on the above profile:

1. **Required**: RV64I — always needed as the base ISA.
2. **Required if present**: M extension — if the compiler uses mul/div for
   index arithmetic, the Jasmin port must target at least RV64IM.
3. **Compressed (C)**: The Jasmin assembler will emit C instructions
   automatically when targeting rv64gc. No explicit handling needed.
4. **Atomics (A)**: Only needed if the Jasmin port uses concurrent data
   structures. XMSS algorithm code is single-threaded; A instructions
   appearing here are from libc.
5. **Float (F/D)**: Should be absent. If present, flag as a bug in the
   C implementation (possibly a compiler quirk with -march=rv64gc enabling
   float ABI).
6. **Zb (bit-manipulation)**: The C compiler with -march=rv64gc does NOT
   emit Zb instructions by default (Zb is not part of rv64gc). If the Jasmin
   port targets rv64gc_zbb (for example), it can use \`ror\`, \`rev8\`, \`clz\`
   explicitly for SHA-2/SHAKE — gaining performance without breaking
   compatibility with standard rv64gc hardware.

### Recommended Jasmin target ISA

- Minimum: \`rv64imac\` (or \`rv64gc\` which equals \`rv64imafd_zicsr_zifencei_c\`)
- Optimised: \`rv64gc_zbb\` to exploit Zbb rotates and byte-reversal in SHA-2

JASMIN

} > "${REPORT}"

echo "Done. Report written to: ${REPORT}"
