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
        else
            # Real instruction: first word is the mnemonic
            mnem="$(echo "$line" | awk '{print $1}')"
        fi

        [[ -z "$mnem" ]] && continue

        printf '%s\t%s\n' "$mnem" "$ext" >> "${RAW}"
    done < "$extfile"
done

# De-duplicate: if the same mnemonic appears in multiple files, keep the
# most specific (rv64_ > rv_). Since rv64_ files are processed after rv_,
# the last occurrence wins. Also, some pseudos appear in extension files
# they don't semantically belong to (e.g. frcsr is a pseudo in rv_f but
# maps to Zicsr). We keep the file-of-origin mapping which is correct
# for our purposes.
#
# Sort by mnemonic, keep last occurrence of each mnemonic.
sort -t$'\t' -k1,1 -s "${RAW}" | awk -F'\t' '
{
    ext[$1] = $2
}
END {
    for (m in ext) print m "\t" ext[m]
}
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
