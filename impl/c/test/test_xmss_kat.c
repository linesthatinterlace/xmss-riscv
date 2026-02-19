/**
 * test_xmss_kat.c - Known Answer Tests cross-validated against xmss-reference
 *
 * Uses BDS-accelerated keygen/sign for practical performance.
 *
 * For each of the 4 h=10 XMSS parameter sets, we:
 *   1. Replay deterministic seeds (seed[i] = i for i = 0..3n-1)
 *   2. Keygen (BDS)
 *   3. SHAKE128-fingerprint pk (without OID) — validates tree root
 *   4. Advance BDS state to idx=512 by signing 512 dummy messages
 *   5. Sign single-byte message {37} at idx=512
 *   6. SHAKE128-fingerprint sig — validates auth path at idx=512
 *   7. Compare against fingerprints from xmss-reference test/vectors.c
 *
 * Reference SK layout (no OID): idx | SK_SEED | SK_PRF | root | PUB_SEED
 * Our SK layout:                OID(4) | idx | SK_SEED | SK_PRF | root | PUB_SEED
 *
 * Reference PK layout (no OID): root | PUB_SEED
 * Our PK layout:                OID(4) | root | PUB_SEED
 *
 * Signature layout is the same: idx | r | sig_WOTS | auth
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "test_utils.h"
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"
#include "../include/xmss/xmss.h"
#include "../src/hash/shake_local.h"
#include "../src/utils.h"

/* Replay-style randombytes: produces exact seed bytes from a buffer */
static uint8_t kat_seed_buf[3 * XMSS_MAX_N];
static size_t  kat_seed_off;

static int kat_randombytes(uint8_t *buf, size_t len)
{
    memcpy(buf, kat_seed_buf + kat_seed_off, len);
    kat_seed_off += len;
    return 0;
}

/* Reference fingerprints from xmss-reference test/vectors.c
 * Generated with: seed[i]=i, keygen, set idx=512, sign msg={37}
 * Fingerprint = SHAKE128(data, len) truncated to 10 bytes */
typedef struct {
    uint32_t    oid;
    const char *name;
    const char *pk_hash;  /* SHAKE128(pk_without_oid, pk_bytes-4) -> 10 bytes hex */
    const char *sig_hash; /* SHAKE128(sig, sig_bytes) -> 10 bytes hex */
} kat_vector_t;

static const kat_vector_t vectors[] = {
    { OID_XMSS_SHA2_10_256,  "XMSS-SHA2_10_256",
      "7de72d192121f414d4bb", "8b6cb278d50a3694ca38" },
    { OID_XMSS_SHA2_10_512,  "XMSS-SHA2_10_512",
      "74ee7c42b4e42a424ed9", "b9e63b0376a550eabe1b" },
    { OID_XMSS_SHAKE_10_256, "XMSS-SHAKE_10_256",
      "764614ee2ce5e4bf0114", "3e9035cffa0fd4be98bd" },
    { OID_XMSS_SHAKE_10_512, "XMSS-SHAKE_10_512",
      "e47fe831b6ee463e2881", "ce2dc09cd7ad8c87ae06" },
};

#define NUM_VECTORS (sizeof(vectors) / sizeof(vectors[0]))

static void run_kat(const kat_vector_t *v)
{
    xmss_params p;
    xmss_bds_state *state;
    uint8_t *pk, *sk, *sig;
    uint8_t msg[1] = {37};
    uint8_t dummy[1] = {0};
    uint8_t fp[10], expected[10];
    char label[128];
    uint32_t i;
    uint32_t target_idx;

    if (xmss_params_from_oid(&p, v->oid) != 0) {
        snprintf(label, sizeof(label), "%s: params", v->name);
        TEST(label, 0);
        return;
    }

    pk    = (uint8_t *)malloc(p.pk_bytes);
    sk    = (uint8_t *)malloc(p.sk_bytes);
    sig   = (uint8_t *)malloc(p.sig_bytes);
    state = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
    if (!pk || !sk || !sig || !state) {
        TEST("malloc", 0);
        free(pk); free(sk); free(sig); free(state);
        return;
    }

    /* Fill seed buffer: seed[i] = i for i = 0..3n-1 */
    for (i = 0; i < 3 * p.n; i++) {
        kat_seed_buf[i] = (uint8_t)i;
    }
    kat_seed_off = 0;

    /* Keygen with deterministic seeds (BDS) */
    if (xmss_keygen(&p, pk, sk, state, 0, kat_randombytes) != XMSS_OK) {
        snprintf(label, sizeof(label), "%s: keygen", v->name);
        TEST(label, 0);
        goto done;
    }

    /* Verify PK fingerprint (skip 4-byte OID to match reference layout) */
    shake128_local(fp, 10, pk + 4, p.pk_bytes - 4);
    hex_decode(expected, v->pk_hash, 10);
    snprintf(label, sizeof(label), "%s: pk fingerprint", v->name);
    if (memcmp(fp, expected, 10) != 0) {
        TEST(label, 0);
        hex_print("  expected", expected, 10);
        hex_print("  got     ", fp, 10);
    } else {
        TEST(label, 1);
    }

    /* Advance BDS state to idx=512 by signing dummy messages */
    target_idx = (uint32_t)1 << (p.h - 1);  /* 512 for h=10 */
    for (i = 0; i < target_idx; i++) {
        if (xmss_sign(&p, sig, dummy, 1, sk, state, 0) != XMSS_OK) {
            snprintf(label, sizeof(label), "%s: advance sign idx=%u", v->name, i);
            TEST(label, 0);
            goto done;
        }
    }

    /* Sign the KAT message at idx=512 */
    if (xmss_sign(&p, sig, msg, 1, sk, state, 0) != XMSS_OK) {
        snprintf(label, sizeof(label), "%s: kat sign", v->name);
        TEST(label, 0);
        goto done;
    }

    /* Verify signature fingerprint */
    shake128_local(fp, 10, sig, p.sig_bytes);
    hex_decode(expected, v->sig_hash, 10);
    snprintf(label, sizeof(label), "%s: sig fingerprint", v->name);
    if (memcmp(fp, expected, 10) != 0) {
        TEST(label, 0);
        hex_print("  expected", expected, 10);
        hex_print("  got     ", fp, 10);
    } else {
        TEST(label, 1);
    }

    /* Also verify the signature is valid */
    {
        int rc = xmss_verify(&p, msg, 1, sig, pk);
        snprintf(label, sizeof(label), "%s: verify own sig", v->name);
        TEST(label, rc == XMSS_OK);
    }

done:
    free(pk);
    free(sk);
    free(sig);
    free(state);
}

int main(void)
{
    size_t i;

    printf("=== test_xmss_kat (cross-validated against xmss-reference) ===\n");

    for (i = 0; i < NUM_VECTORS; i++) {
        printf("--- %s ---\n", vectors[i].name);
        run_kat(&vectors[i]);
    }

    return tests_done();
}
