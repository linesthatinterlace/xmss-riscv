/**
 * test_xmss_acvp_kat.c — NIST ACVP cross-validation for XMSS (SHA2, N32).
 *
 * Uses vectors from third_party/post-quantum-crypto-kat (generated into
 * xmss_acvp_vectors.h by gen_acvp_vectors.py).
 *
 * Scope: SHA2 N32 only. ACVP SHAKE256 OIDs 16-18 are NIST SP 800-208 (SHAKE256);
 * RFC 8391 XMSS-SHAKE uses SHAKE128 — different algorithm, excluded.
 *
 * keyGen (H10): feed S_XMSS||SK_PRF||I via replay randombytes, call xmss_keygen(),
 *   compare pk and sk directly.
 *
 * sigGen (H10): one keygen with group seeds, then sign sequentially to each q
 *   (sorted ascending), compare full RFC 8391 signature bytes.
 *
 * sigVer (H10/H16/H20): call xmss_verify() with provided pk, message, sig;
 *   check pass/fail matches expected.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"
#include "xmss_acvp_vectors.h"
#include "../include/xmss/params.h"
#include "../include/xmss/xmss.h"

/* Replay-style randombytes */
static const uint8_t *replay_buf;
static size_t         replay_off;

static int replay_randombytes(uint8_t *out, size_t len)
{
    memcpy(out, replay_buf + replay_off, len);
    replay_off += len;
    return 0;
}

/* ===== keyGen ===== */

static void run_keygen(void)
{
    const acvp_keygen_case_t *vec;
    xmss_params p;
    uint8_t *pk, *sk;
    xmss_bds_state *state;
    uint8_t seed_buf[96]; /* S_XMSS(32) || SK_PRF(32) || I(32) */
    char label[128];
    int i;

    printf("--- keyGen (SHA2-N32-H10) ---\n");

    for (i = 0; i < ACVP_KEYGEN_SHA2_N32_H10_COUNT; i++) {
        vec = &acvp_keygen_sha2_n32_h10[i];

        if (xmss_params_from_oid(&p, vec->oid) != 0) {
            snprintf(label, sizeof(label), "keyGen[%d]: params", i + 1);
            TEST(label, 0);
            continue;
        }

        pk    = (uint8_t *)malloc(p.pk_bytes);
        sk    = (uint8_t *)malloc(p.sk_bytes);
        state = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
        if (!pk || !sk || !state) { TEST("malloc", 0); free(pk); free(sk); free(state); continue; }

        memcpy(seed_buf,      vec->s_xmss, 32);
        memcpy(seed_buf + 32, vec->sk_prf, 32);
        memcpy(seed_buf + 64, vec->i_seed, 32);
        replay_buf = seed_buf;
        replay_off = 0;

        if (xmss_keygen(&p, pk, sk, state, 0, replay_randombytes) != XMSS_OK) {
            snprintf(label, sizeof(label), "keyGen[%d]: keygen", i + 1);
            TEST(label, 0);
            free(pk); free(sk); free(state);
            continue;
        }

        snprintf(label, sizeof(label), "keyGen[%d]: pk", i + 1);
        TEST_BYTES(label, pk, vec->pk, (size_t)p.pk_bytes);

        snprintf(label, sizeof(label), "keyGen[%d]: sk", i + 1);
        TEST_BYTES(label, sk, vec->sk, (size_t)p.sk_bytes);

        free(pk); free(sk); free(state);
    }
}

/* ===== sigGen ===== */

/* Comparison helper for qsort: sort siggen cases by q ascending */
static int cmp_q(const void *a, const void *b)
{
    uint32_t qa = ((const acvp_siggen_case_t *)a)->q;
    uint32_t qb = ((const acvp_siggen_case_t *)b)->q;
    return (qa > qb) - (qa < qb);
}

static void run_siggen(void)
{
    const acvp_siggen_group_t *grp = &acvp_siggen_sha2_n32_h10;
    xmss_params p;
    uint8_t *pk, *sk, *sig;
    xmss_bds_state *state;
    uint8_t seed_buf[96];
    uint8_t dummy[1] = {0};
    acvp_siggen_case_t sorted[10];
    uint32_t cur_idx;
    char label[128];
    int i;

    printf("--- sigGen (SHA2-N32-H10) ---\n");

    if (xmss_params_from_oid(&p, grp->oid) != 0) { TEST("sigGen: params", 0); return; }

    pk    = (uint8_t *)malloc(p.pk_bytes);
    sk    = (uint8_t *)malloc(p.sk_bytes);
    sig   = (uint8_t *)malloc(p.sig_bytes);
    state = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
    if (!pk || !sk || !sig || !state) { TEST("malloc", 0); free(pk); free(sk); free(sig); free(state); return; }

    memcpy(seed_buf,      grp->s_xmss, 32);
    memcpy(seed_buf + 32, grp->sk_prf, 32);
    memcpy(seed_buf + 64, grp->i_seed, 32);
    replay_buf = seed_buf;
    replay_off = 0;

    if (xmss_keygen(&p, pk, sk, state, 0, replay_randombytes) != XMSS_OK) {
        TEST("sigGen: keygen", 0);
        goto done;
    }

    TEST_BYTES("sigGen: pk", pk, grp->pk, (size_t)p.pk_bytes);

    /* Sort cases by q so we can sign sequentially */
    memcpy(sorted, grp->cases, (size_t)grp->num_cases * sizeof(acvp_siggen_case_t));
    qsort(sorted, (size_t)grp->num_cases, sizeof(acvp_siggen_case_t), cmp_q);

    cur_idx = 0;
    for (i = 0; i < grp->num_cases; i++) {
        const acvp_siggen_case_t *tc = &sorted[i];

        /* Advance to tc->q by signing dummies */
        while (cur_idx < tc->q) {
            if (xmss_sign(&p, sig, dummy, 1, sk, state, 0) != XMSS_OK) {
                snprintf(label, sizeof(label), "sigGen: advance to q=%u", tc->q);
                TEST(label, 0);
                goto done;
            }
            cur_idx++;
        }

        /* Sign the test message at q */
        if (xmss_sign(&p, sig, tc->msg, ACVP_MSG_LEN, sk, state, 0) != XMSS_OK) {
            snprintf(label, sizeof(label), "sigGen: sign q=%u", tc->q);
            TEST(label, 0);
            goto done;
        }
        cur_idx++;

        snprintf(label, sizeof(label), "sigGen: sig q=%u", tc->q);
        TEST_BYTES(label, sig, tc->sig, (size_t)p.sig_bytes);
    }

done:
    free(pk); free(sk); free(sig); free(state);
}

/* ===== sigVer ===== */

static void run_sigver_group(const acvp_sigver_group_t *grp)
{
    xmss_params p;
    char label[128];
    int i, rc, pass;

    if (xmss_params_from_oid(&p, grp->oid) != 0) {
        snprintf(label, sizeof(label), "sigVer oid=0x%08x: params", grp->oid);
        TEST(label, 0);
        return;
    }

    for (i = 0; i < grp->num_cases; i++) {
        const acvp_sigver_case_t *tc = &grp->cases[i];
        rc   = xmss_verify(&p, tc->msg, ACVP_MSG_LEN, tc->sig, grp->pk);
        pass = (rc == XMSS_OK) ? 1 : 0;
        snprintf(label, sizeof(label), "sigVer[%d] h=%u %s",
                 i + 1, p.h, tc->expected_pass ? "valid" : "invalid");
        TEST(label, pass == tc->expected_pass);
    }
}

static void run_sigver(void)
{
    printf("--- sigVer (SHA2-N32-H10) ---\n");
    run_sigver_group(&acvp_sigver_sha2_n32_h10);
    printf("--- sigVer (SHA2-N32-H16) ---\n");
    run_sigver_group(&acvp_sigver_sha2_n32_h16);
    printf("--- sigVer (SHA2-N32-H20) ---\n");
    run_sigver_group(&acvp_sigver_sha2_n32_h20);
}

int main(void)
{
    printf("=== test_xmss_acvp_kat (NIST ACVP cross-validation, SHA2 N32) ===\n");
    run_keygen();
    run_siggen();
    run_sigver();
    return tests_done();
}
