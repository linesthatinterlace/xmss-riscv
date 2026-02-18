#!/usr/bin/env bash
# isa/scripts/gen_lookup.sh
#
# Generate an authoritative mnemonic→extension lookup table from the
# riscv-opcodes submodule (third_party/riscv-opcodes/).
#
# Output: TSV file (mnemonic<TAB>extension) written to stdout or to the
# path given as $1 (default: isa/scripts/mnemonic_extensions.tsv).
#
# The lookup covers all ratified RV64 extensions (rv_* and rv64_* files).
# Pseudo-ops ($pseudo_op lines) are included, tagged to the extension
# of the file they appear in.
#
# For C extension mnemonics (c.addi, c.ld, etc.), a de-aliased entry
# without the "c." prefix is also emitted, so that when objdump renders
# a compressed instruction as its uncompressed alias (e.g. "sd" instead
# of "c.sd"), it still maps to the correct semantic extension.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OPCODES_DIR="${REPO_ROOT}/third_party/riscv-opcodes/extensions"
OUTPUT="${1:-${SCRIPT_DIR}/mnemonic_extensions.tsv}"

if [[ ! -d "${OPCODES_DIR}" ]]; then
    echo "ERROR: riscv-opcodes submodule not found at ${OPCODES_DIR}" >&2
    echo "       Run: git submodule update --init third_party/riscv-opcodes" >&2
    exit 1
fi

# derive_extension <filename>
# Maps filename to canonical extension name.
# Examples: rv_i → I, rv64_i → I, rv_m → M, rv64_zbb → Zbb, rv_c → C
derive_extension() {
    local name="$1"
    # Strip rv_ or rv32_ or rv64_ prefix
    local ext="${name#rv_}"
    ext="${ext#rv32_}"
    ext="${ext#rv64_}"
    # Capitalise: first char upper, rest as-is
    # Special cases: single letter → uppercase; z* → Z + rest
    case "$ext" in
        [a-z])      echo "${ext^^}" ;;          # i→I, m→M, a→A, c→C, etc.
        z*)         echo "Z${ext:1}" ;;         # zbb→Zbb, zba→Zba, zbs→Zbs
        [a-z]_*)    echo "${ext%%_*}" | tr '[:lower:]' '[:upper:]' ;;  # c_d→C
        *)          echo "$ext" ;;
    esac
}

# Temporary workspace
TMPDIR_BASE="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_BASE}"' EXIT

RAW="${TMPDIR_BASE}/raw.tsv"
> "${RAW}"

# Process each extension file (rv_* and rv64_* only; skip rv32_* and unratified)
for extfile in "${OPCODES_DIR}"/rv_* "${OPCODES_DIR}"/rv64_*; do
    [[ -f "$extfile" ]] || continue
    fname="$(basename "$extfile")"

    # Skip combined/alias files that would cause duplicates
    case "$fname" in
        rv_v_aliases|rv_zk|rv_zkn|rv_zks|rv_zvkn|rv_zvks) continue ;;
        rv64_zk|rv64_zkn|rv64_zks) continue ;;
    esac

    ext="$(derive_extension "$fname")"

    while IFS= read -r line; do
        # Skip blank lines and comments
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue

        if [[ "$line" =~ ^\$ ]] && [[ ! "$line" =~ ^\$pseudo_op ]]; then
            # Skip non-pseudo directives ($import, etc.)
            continue
        elif [[ "$line" =~ ^\$pseudo_op ]]; then
            # Format: $pseudo_op <ext>::<base_insn> <pseudo_mnemonic> <operands...>
            # The pseudo mnemonic is the third whitespace-delimited field
            mnem="$(echo "$line" | awk '{print $3}')"
            is_pseudo=1
        else
            # Real instruction: first word is the mnemonic
            mnem="$(echo "$line" | awk '{print $1}')"
            is_pseudo=0
        fi

        [[ -z "$mnem" ]] && continue

        # Priority: real rv64_ (1) > real rv_ (2) > pseudo rv64_ (3) > pseudo rv_ (4)
        # Lower number = higher priority. Used during dedup to prefer the
        # "defining" extension over re-exports (e.g. rev8 is defined in Zbb
        # but re-exported as a pseudo in Zbkb; we want Zbb).
        if [[ "$is_pseudo" -eq 0 ]]; then
            if [[ "$fname" == rv64_* ]]; then pri=1; else pri=2; fi
        else
            if [[ "$fname" == rv64_* ]]; then pri=3; else pri=4; fi
        fi

        printf '%s\t%s\t%s\n' "$mnem" "$ext" "$pri" >> "${RAW}"
    done < "$extfile"
done

# De-duplicate: when the same mnemonic appears in multiple extension files,
# keep the highest-priority entry (lowest priority number). This ensures
# that the "defining" extension wins over re-exports. For example, rev8 is
# a real instruction in rv64_zbb (pri=1) but a $pseudo_op in rv64_zbkb
# (pri=3), so we keep Zbb.
sort -t$'\t' -k1,1 -k3,3n -s "${RAW}" | awk -F'\t' '
!seen[$1]++ { print $1 "\t" $2 }
' | sort -t$'\t' -k1,1 > "${TMPDIR_BASE}/deduped.tsv"

# For C extension mnemonics (c.xxx), also emit the de-aliased form (xxx)
# mapped to the SEMANTIC extension of the base instruction. objdump renders
# compressed instructions using the base mnemonic (e.g. "sd" not "c.sd").
# These de-aliased entries do NOT override existing base entries.
awk -F'\t' '/^c\./ {
    base = substr($1, 3)   # strip "c." prefix
    print base "\t" "I"    # C instructions alias RV64I/M base ops
}' "${TMPDIR_BASE}/deduped.tsv" > "${TMPDIR_BASE}/c_aliases.tsv"

# Merge: base entries take priority over C aliases
cat "${TMPDIR_BASE}/deduped.tsv" "${TMPDIR_BASE}/c_aliases.tsv" \
| sort -t$'\t' -k1,1 -s \
| awk -F'\t' '!seen[$1]++ {print}' \
> "${TMPDIR_BASE}/merged.tsv"

# Add manual supplement for objdump-specific pseudo-instructions that are
# NOT in the riscv-opcodes database. These are assembler/disassembler
# conventions documented in the RISC-V ISA manual pseudoinstruction tables.
cat >> "${TMPDIR_BASE}/merged.tsv" <<'SUPPLEMENT'
li	I
la	I
not	I
negw	I
seqz	I
snez	I
sltz	I
sgtz	I
beqz	I
bnez	I
bltz	I
bgez	I
bgtz	I
blez	I
j	I
jr	I
call	I
tail	I
SUPPLEMENT

# Final de-duplicate (manual entries don't override riscv-opcodes entries)
sort -t$'\t' -k1,1 -s "${TMPDIR_BASE}/merged.tsv" \
| awk -F'\t' '!seen[$1]++ {print}' \
> "${OUTPUT}"

TOTAL="$(wc -l < "${OUTPUT}")"
echo "Generated ${OUTPUT} (${TOTAL} entries)" >&2
