#!/usr/bin/env python3
"""
gen_acvp_vectors.py — Generate xmss_acvp_vectors.h from NIST ACVP KAT JSON.

Source: third_party/post-quantum-crypto-kat/XMSS/
Output: impl/c/test/xmss_acvp_vectors.h

Scope: SHA2 N32 (n=32) parameter sets only.
  - SHA2 ACVP OIDs 1/2/3 match RFC 8391 OIDs OID_XMSS_SHA2_{10,16,20}_256.
  - SHAKE256 ACVP OIDs 16-18 are NIST SP 800-208 (different hash function
    from RFC 8391's XMSS-SHAKE which uses SHAKE128). Excluded.

ACVP "signature" format: RFC_sig || message (128 bytes appended).
  RFC sig sizes: H10=2500, H16=2692, H20=2820 bytes.

Usage: run from the repository root.
  python3 impl/c/test/gen_acvp_vectors.py
"""

import json
import math
import os
import sys

KAT_ROOT = "third_party/post-quantum-crypto-kat/XMSS"
OUT_FILE = "impl/c/test/xmss_acvp_vectors.h"

# RFC 8391 signature bytes for XMSS (n=32, w=16)
def rfc_sig_bytes(h, n=32, w=16):
    len1 = math.ceil(8 * n / math.log2(w))
    len2 = math.floor(math.log2(len1 * (w - 1)) / math.log2(w)) + 1
    return 4 + n + (len1 + len2) * n + h * n

RFC_SIG = {10: rfc_sig_bytes(10), 16: rfc_sig_bytes(16), 20: rfc_sig_bytes(20)}
MSG_LEN = 128   # all messages in sigGen/sigVer are 128 bytes
PK_LEN  = 68    # OID(4) + root(32) + PUB_SEED(32)
SK_LEN  = 136   # OID(4) + idx(4) + SK_SEED(32) + SK_PRF(32) + root(32) + PUB_SEED(32)

# ACVP OID → our macro name (SHA2 N32 only)
OID_TO_MACRO = {1: "OID_XMSS_SHA2_10_256", 2: "OID_XMSS_SHA2_16_256", 3: "OID_XMSS_SHA2_20_256"}

def hex_c_array(data: bytes, indent: int = 8) -> str:
    """Format bytes as a C hex literal array body (no braces)."""
    pad = " " * indent
    chunks = [data[i:i+16] for i in range(0, len(data), 16)]
    lines = [pad + ", ".join(f"0x{b:02x}" for b in chunk) for chunk in chunks]
    return ",\n".join(lines)

def load_json(path):
    with open(path) as f:
        return json.load(f)

def emit_keygen(out, heights=(10,)):
    """keyGen: seeds → expected pk + sk. H10 only (H16/H20 keygen is too slow)."""
    out.write("/* ===== keyGen vectors (SHA2, N32) ===== */\n\n")
    out.write("typedef struct {\n")
    out.write("    uint32_t oid;\n")
    out.write(f"    uint8_t  s_xmss[32]; /* SK_SEED input */\n")
    out.write(f"    uint8_t  sk_prf[32]; /* SK_PRF input */\n")
    out.write(f"    uint8_t  i_seed[32]; /* PUB_SEED (I) input */\n")
    out.write(f"    uint8_t  pk[{PK_LEN}];  /* expected publicKey */\n")
    out.write(f"    uint8_t  sk[{SK_LEN}]; /* expected secretKey */\n")
    out.write("} acvp_keygen_case_t;\n\n")

    for h in heights:
        dname = f"XMSS-keyGen-SHA256-N32-H{h}"
        prompt = load_json(f"{KAT_ROOT}/{dname}/prompt.json")
        results = load_json(f"{KAT_ROOT}/{dname}/expectedResults.json")
        g = prompt["testGroups"][0]
        gr = results["testGroups"][0]
        oid = g["OID"]
        macro = OID_TO_MACRO[oid]
        varname = f"acvp_keygen_sha2_n32_h{h}"
        out.write(f"static const acvp_keygen_case_t {varname}[] = {{\n")
        for tc, tcr in zip(g["tests"], gr["tests"]):
            assert tc["tcId"] == tcr["tcId"]
            s_xmss = bytes.fromhex(tc["S_XMSS"])
            sk_prf = bytes.fromhex(tc["SK_PRF"])
            i_seed = bytes.fromhex(tc["I"])
            pk     = bytes.fromhex(tcr["publicKey"])
            sk     = bytes.fromhex(tcr["secretKey"])
            assert len(pk) == PK_LEN, f"pk len {len(pk)} != {PK_LEN}"
            assert len(sk) == SK_LEN, f"sk len {len(sk)} != {SK_LEN}"
            out.write(f"    /* tcId={tc['tcId']} */\n")
            out.write(f"    {{\n")
            out.write(f"        {macro},\n")
            out.write(f"        /* s_xmss */ {{{hex_c_array(s_xmss, 0)}}},\n")
            out.write(f"        /* sk_prf  */ {{{hex_c_array(sk_prf, 0)}}},\n")
            out.write(f"        /* i_seed  */ {{{hex_c_array(i_seed, 0)}}},\n")
            out.write(f"        /* pk */\n")
            out.write(f"        {{\n{hex_c_array(pk)}\n        }},\n")
            out.write(f"        /* sk */\n")
            out.write(f"        {{\n{hex_c_array(sk)}\n        }}\n")
            out.write(f"    }},\n")
        out.write(f"}};\n")
        out.write(f"#define ACVP_KEYGEN_SHA2_N32_H{h}_COUNT "
                  f"((int)(sizeof({varname}) / sizeof({varname}[0])))\n\n")

def emit_siggen(out):
    """sigGen: keygen with group seeds, sign at each q, compare RFC sig."""
    out.write("/* ===== sigGen vectors (SHA2, N32, H10 only) ===== */\n\n")
    sig_len = RFC_SIG[10]
    out.write(f"typedef struct {{\n")
    out.write(f"    uint8_t  msg[{MSG_LEN}];\n")
    out.write(f"    uint32_t q;         /* leaf index */\n")
    out.write(f"    uint8_t  sig[{sig_len}]; /* RFC 8391 signature */\n")
    out.write(f"}} acvp_siggen_case_t;\n\n")

    out.write(f"typedef struct {{\n")
    out.write(f"    uint32_t oid;\n")
    out.write(f"    uint8_t  s_xmss[32];\n")
    out.write(f"    uint8_t  sk_prf[32];\n")
    out.write(f"    uint8_t  i_seed[32];\n")
    out.write(f"    uint8_t  pk[{PK_LEN}];\n")
    out.write(f"    int      num_cases;\n")
    out.write(f"    acvp_siggen_case_t cases[10];\n")
    out.write(f"}} acvp_siggen_group_t;\n\n")

    dname = "XMSS-sigGen-SHA256-N32-H10"
    prompt  = load_json(f"{KAT_ROOT}/{dname}/prompt.json")
    results = load_json(f"{KAT_ROOT}/{dname}/expectedResults.json")
    g  = prompt["testGroups"][0]
    gr = results["testGroups"][0]
    oid = g["OID"]
    macro = OID_TO_MACRO[oid]
    s_xmss = bytes.fromhex(g["S_XMSS"])
    sk_prf = bytes.fromhex(g["SK_PRF"])
    i_seed = bytes.fromhex(g["I"])
    pk     = bytes.fromhex(gr["publicKey"])  # group-level in expectedResults

    out.write(f"static const acvp_siggen_group_t acvp_siggen_sha2_n32_h10 = {{\n")
    out.write(f"    {macro},\n")
    out.write(f"    /* s_xmss */ {{{hex_c_array(s_xmss, 0)}}},\n")
    out.write(f"    /* sk_prf  */ {{{hex_c_array(sk_prf, 0)}}},\n")
    out.write(f"    /* i_seed  */ {{{hex_c_array(i_seed, 0)}}},\n")
    out.write(f"    /* pk */\n    {{\n{hex_c_array(pk)}\n    }},\n")
    out.write(f"    {len(g['tests'])},\n")
    out.write(f"    /* cases */\n    {{\n")
    for tc, tcr in zip(g["tests"], gr["tests"]):
        assert tc["tcId"] == tcr["tcId"]
        msg = bytes.fromhex(tc["message"])
        q   = tc["q"]
        # ACVP sig = RFC_sig || message; extract RFC portion
        full_sig = bytes.fromhex(tcr["signature"])
        rfc_sig  = full_sig[:sig_len]
        assert full_sig[sig_len:] == msg, f"appended message mismatch tcId={tc['tcId']}"
        # Verify idx in sig matches q
        idx_in_sig = int.from_bytes(rfc_sig[:4], 'big')
        assert idx_in_sig == q, f"idx={idx_in_sig} != q={q}"
        out.write(f"        /* tcId={tc['tcId']} q={q} */\n")
        out.write(f"        {{\n")
        out.write(f"            /* msg */\n            {{{hex_c_array(msg, 12)}}},\n")
        out.write(f"            {q}u,\n")
        out.write(f"            /* sig */\n            {{\n{hex_c_array(rfc_sig, 12)}\n            }}\n")
        out.write(f"        }},\n")
    out.write(f"    }}\n}};\n\n")

def emit_sigver(out, heights=(10, 16, 20)):
    """sigVer: pk + message + RFC_sig → pass/fail."""
    max_sig = max(RFC_SIG[h] for h in heights)
    out.write("/* ===== sigVer vectors (SHA2, N32) ===== */\n\n")
    out.write(f"#define ACVP_SIGVER_MAX_SIG {max_sig}\n\n")
    out.write(f"typedef struct {{\n")
    out.write(f"    uint8_t  msg[{MSG_LEN}];\n")
    out.write(f"    uint8_t  sig[ACVP_SIGVER_MAX_SIG];\n")
    out.write(f"    size_t   sig_len; /* actual RFC sig bytes for this param set */\n")
    out.write(f"    int      expected_pass; /* 1=valid, 0=invalid */\n")
    out.write(f"}} acvp_sigver_case_t;\n\n")
    out.write(f"typedef struct {{\n")
    out.write(f"    uint32_t oid;\n")
    out.write(f"    uint8_t  pk[{PK_LEN}];\n")
    out.write(f"    int      num_cases;\n")
    out.write(f"    acvp_sigver_case_t cases[10];\n")
    out.write(f"}} acvp_sigver_group_t;\n\n")

    for h in heights:
        dname = f"XMSS-sigVer-SHA256-N32-H{h}"
        prompt  = load_json(f"{KAT_ROOT}/{dname}/prompt.json")
        results = load_json(f"{KAT_ROOT}/{dname}/expectedResults.json")
        g  = prompt["testGroups"][0]
        gr = results["testGroups"][0]
        oid = g["OID"]
        macro = OID_TO_MACRO[oid]
        pk = bytes.fromhex(g["publicKey"])
        assert len(pk) == PK_LEN
        sig_len = RFC_SIG[h]
        varname = f"acvp_sigver_sha2_n32_h{h}"
        out.write(f"static const acvp_sigver_group_t {varname} = {{\n")
        out.write(f"    {macro},\n")
        out.write(f"    /* pk */\n    {{\n{hex_c_array(pk)}\n    }},\n")
        out.write(f"    {len(g['tests'])},\n")
        out.write(f"    /* cases */\n    {{\n")
        pass_map = {tc["tcId"]: tc["testPassed"] for tc in gr["tests"]}
        for tc in g["tests"]:
            msg = bytes.fromhex(tc["message"])
            full_sig = bytes.fromhex(tc["signature"])
            rfc_sig = full_sig[:sig_len]
            expected = 1 if pass_map[tc["tcId"]] else 0
            out.write(f"        /* tcId={tc['tcId']} {tc['comment']} expected={'PASS' if expected else 'FAIL'} */\n")
            out.write(f"        {{\n")
            out.write(f"            /* msg */\n            {{{hex_c_array(msg, 12)}}},\n")
            # pad sig to ACVP_SIGVER_MAX_SIG
            padded = rfc_sig + bytes(max_sig - len(rfc_sig))
            out.write(f"            /* sig (padded to ACVP_SIGVER_MAX_SIG) */\n")
            out.write(f"            {{\n{hex_c_array(padded, 12)}\n            }},\n")
            out.write(f"            {sig_len}, /* sig_len */\n")
            out.write(f"            {expected}  /* expected_pass */\n")
            out.write(f"        }},\n")
        out.write(f"    }}\n}};\n\n")

def main():
    if not os.path.isdir(KAT_ROOT):
        print(f"ERROR: {KAT_ROOT} not found. Run from repo root with submodule checked out.",
              file=sys.stderr)
        sys.exit(1)

    with open(OUT_FILE, "w") as out:
        out.write("/* xmss_acvp_vectors.h — AUTO-GENERATED by gen_acvp_vectors.py */\n")
        out.write("/* DO NOT EDIT BY HAND. Re-run: python3 impl/c/test/gen_acvp_vectors.py */\n")
        out.write("/*\n")
        out.write(" * Source: NIST ACVP KAT vectors (SHA2 N32 only).\n")
        out.write(" * ACVP SHAKE256 OIDs 16-18 are NIST SP 800-208 and use SHAKE256;\n")
        out.write(" * RFC 8391 XMSS-SHAKE uses SHAKE128. Excluded from this file.\n")
        out.write(" *\n")
        out.write(" * ACVP signature format: RFC_sig || message (128-byte message appended).\n")
        out.write(" * Only the RFC_sig portion is stored in sigGen/sigVer structs here.\n")
        out.write(" */\n")
        out.write("#ifndef XMSS_ACVP_VECTORS_H\n")
        out.write("#define XMSS_ACVP_VECTORS_H\n\n")
        out.write("#include <stddef.h>\n")
        out.write("#include <stdint.h>\n")
        out.write('#include "../include/xmss/params.h"\n\n')
        out.write(f"#define ACVP_MSG_LEN {MSG_LEN}  /* message length in sigGen/sigVer */\n\n")
        emit_keygen(out, heights=[10])
        emit_siggen(out)
        emit_sigver(out, heights=[10, 16, 20])
        out.write("#endif /* XMSS_ACVP_VECTORS_H */\n")

    print(f"Written: {OUT_FILE}")

if __name__ == "__main__":
    main()
