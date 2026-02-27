/*
 * crypto wrapper functions for mbed TLS
 *
 * SPDX-FileCopyrightText: 2022 Glenn Strauss <gstrauss@gluelogic.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "utils/includes.h"
#include "utils/common.h"

#ifndef CONFIG_WIFI_NM_WPA_SUPPLICANT_CRYPTO_NONE
#include <mbedtls/version.h>
#include <mbedtls/platform_util.h> /* mbedtls_platform_zeroize() */
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/bignum.h>

#include <psa/crypto.h>
#include <mbedtls/psa_util.h>
#include "supp_psa_api.h"

#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(x) x
#endif

#define ENTROPY_MIN_PLATFORM     32

/* hostapd/wpa_supplicant provides forced_memzero(),
 * but prefer mbedtls_platform_zeroize() */
#define forced_memzero(ptr, sz) mbedtls_platform_zeroize(ptr, sz)

#define IANA_SECP256R1        19
#define IANA_SECP384R1        20
#define IANA_SECP521R1        21

#ifdef CONFIG_MBEDTLS_ECDH_LEGACY_CONTEXT
#define ACCESS_ECDH(S, var) S->MBEDTLS_PRIVATE(var)
#else
#define ACCESS_ECDH(S, var) S->MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(var)
#endif

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef __GNUC_PREREQ
#define __GNUC_PREREQ(maj, min) 0
#endif

#ifndef __attribute_cold__
#if __has_attribute(cold) || __GNUC_PREREQ(4, 3)
#define __attribute_cold__ __attribute__((__cold__))
#else
#define __attribute_cold__
#endif
#endif

#ifndef __attribute_noinline__
#if __has_attribute(noinline) || __GNUC_PREREQ(3, 1)
#define __attribute_noinline__ __attribute__((__noinline__))
#else
#define __attribute_noinline__
#endif
#endif

#include "crypto.h"
#include "aes_wrap.h"
#include "aes.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"

/*
 * selective code inclusion based on preprocessor defines
 *
 * future: additional code could be wrapped with preprocessor checks if
 * wpa_supplicant/Makefile and hostap/Makefile were more consistent with
 * setting preprocessor defines for named groups of functionality
 */

#if defined(EAP_FAST) || defined(EAP_FAST_DYNAMIC) || defined(EAP_SERVER_FAST) || defined(EAP_TEAP) || \
    defined(EAP_TEAP_DYNAMIC) || defined(EAP_SERVER_FAST)
#define CRYPTO_MBEDTLS_SHA1_T_PRF
#endif

#if !defined(CONFIG_NO_PBKDF2)
#define CRYPTO_MBEDTLS_PBKDF2_SHA1
#endif /* pbkdf2_sha1() */

#if defined(EAP_IKEV2) || defined(EAP_IKEV2_DYNAMIC) || defined(EAP_SERVER_IKEV2) /* CONFIG_EAP_IKEV2=y */
#define CRYPTO_MBEDTLS_CRYPTO_CIPHER
#endif /* crypto_cipher_*() */

#if defined(EAP_PWD) || defined(EAP_SERVER_PWD) /* CONFIG_EAP_PWD=y */ \
    || defined(CONFIG_WIFI_NM_WPA_SUPPLICANT_WPA3)                      /* CONFIG_WIFI_NM_WPA_SUPPLICANT_WPA3=y */
#define CRYPTO_MBEDTLS_CRYPTO_BIGNUM
#endif /* crypto_bignum_*() */

#if defined(EAP_PWD)              /* CONFIG_EAP_PWD=y */   \
    || defined(EAP_EKE)           /* CONFIG_EAP_EKE=y */   \
    || defined(EAP_EKE_DYNAMIC)   /* CONFIG_EAP_EKE=y */   \
    || defined(EAP_SERVER_EKE)    /* CONFIG_EAP_EKE=y */   \
    || defined(EAP_IKEV2)         /* CONFIG_EAP_IKEV2y */  \
    || defined(EAP_IKEV2_DYNAMIC) /* CONFIG_EAP_IKEV2=y */ \
    || defined(EAP_SERVER_IKEV2)  /* CONFIG_EAP_IKEV2=y */ \
    || defined(CONFIG_WIFI_NM_WPA_SUPPLICANT_WPA3)        /* CONFIG_WIFI_NM_WPA_SUPPLICANT_WPA3=y */       \
    || defined(CONFIG_WPS)        /* CONFIG_WPS=y */
#define CRYPTO_MBEDTLS_CRYPTO_DH
#if defined(CONFIG_WPS_NFC)
#define CRYPTO_MBEDTLS_DH5_INIT_FIXED
#endif /* dh5_init_fixed() */
#endif /* crypto_dh_*() */

#if defined(CONFIG_PSA_WANT_ALG_ECDH)
#define CRYPTO_MBEDTLS_CRYPTO_ECDH
#endif /* crypto_ecdh_*() */

#define CRYPTO_MBEDTLS_CRYPTO_BIGNUM

#if defined(CONFIG_DPP) || defined(CONFIG_SAE_PK) || defined(EAP_PWD) \
    || defined(EAP_SERVER_PWD) || defined(CONFIG_WIFI_NM_WPA_SUPPLICANT_WPA3)
#define CRYPTO_MBEDTLS_CRYPTO_EC
#endif

#if defined(CONFIG_DPP)              /* CONFIG_DPP=y */
#define CRYPTO_MBEDTLS_CRYPTO_EC_DPP /* extra for DPP */
#define CRYPTO_MBEDTLS_CRYPTO_CSR
#endif /* crypto_csr_*() */

#if defined(CONFIG_DPP2) /* CONFIG_DPP2=y */
#define CRYPTO_MBEDTLS_CRYPTO_PKCS7
#endif /* crypto_pkcs7_*() */

#if defined(CONFIG_DPP3) /* CONFIG_DPP3=y */
#define CRYPTO_MBEDTLS_CRYPTO_HPKE
#endif

#if defined(EAP_SIM) || defined(EAP_SIM_DYNAMIC) || defined(EAP_SERVER_SIM) || defined(EAP_AKA) || \
    defined(EAP_AKA_DYNAMIC) || defined(EAP_SERVER_AKA) || defined(CONFIG_AP) || defined(HOSTAPD)
/* CONFIG_EAP_SIM=y CONFIG_EAP_AKA=y CONFIG_AP=y HOSTAPD */
#if defined(CRYPTO_RSA_OAEP_SHA256)
#define CRYPTO_MBEDTLS_CRYPTO_RSA
#endif

#endif /* crypto_rsa_*() */

#ifdef CRYPTO_MBEDTLS_CRYPTO_BIGNUM
#include <mbedtls/bignum.h>
static mbedtls_mpi mpi_sw_A;
#endif

__attribute_cold__ void crypto_unload(void)
{
    /* Nothing to do */
}

int hostap_rng_fn(void* ctx, unsigned char* buf, size_t buf_size)
{
    if (psa_generate_random(buf, buf_size) != PSA_SUCCESS) {
        return -1;
    }
    return 0;
}

void *hostap_rng_ctx(void)
{
    return NULL;
}

__attribute_noinline__ static int md_vector(
    size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac, mbedtls_md_type_t md_type)
{
    return md_vector_psa(num_elem, addr, len, mac, md_type);
}

int sha512_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return md_vector(num_elem, addr, len, mac, MBEDTLS_MD_SHA512);
}

int sha384_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return md_vector(num_elem, addr, len, mac, MBEDTLS_MD_SHA384);
}

int sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return md_vector(num_elem, addr, len, mac, MBEDTLS_MD_SHA256);
}

#if defined(CONFIG_PSA_WANT_ALG_SHA_1)
int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return md_vector(num_elem, addr, len, mac, MBEDTLS_MD_SHA1);
}
#endif

#if defined(CONFIG_PSA_WANT_ALG_MD5)
int md5_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return md_vector(num_elem, addr, len, mac, MBEDTLS_MD_MD5);
}
#endif

#ifdef MBEDTLS_MD4_C
#include <mbedtls/md4.h>
int md4_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return md_vector(num_elem, addr, len, mac, MBEDTLS_MD_MD4);
}
#endif

struct crypto_hash
{
    mbedtls_md_context_t ctx;
};

struct crypto_hash *crypto_hash_init(enum crypto_hash_alg alg, const u8 *key, size_t key_len)
{
    struct crypto_hash *ctx;
    mbedtls_md_type_t md_type;
    const mbedtls_md_info_t *md_info;
    int ret = 0;

    switch (alg)
    {
        case CRYPTO_HASH_ALG_HMAC_MD5:
            md_type = MBEDTLS_MD_MD5;
            break;
        case CRYPTO_HASH_ALG_HMAC_SHA1:
            md_type = MBEDTLS_MD_SHA1;
            break;
        case CRYPTO_HASH_ALG_HMAC_SHA256:
            md_type = MBEDTLS_MD_SHA256;
            break;
        case CRYPTO_HASH_ALG_SHA384:
            md_type = MBEDTLS_MD_SHA384;
            break;
        case CRYPTO_HASH_ALG_SHA512:
            md_type = MBEDTLS_MD_SHA512;
            break;
        default:
            return NULL;
    }

    ctx = os_zalloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        return NULL;
    }

    mbedtls_md_init(&ctx->ctx);
    md_info = mbedtls_md_info_from_type(md_type);
    if (!md_info)
    {
        os_free(ctx);
        return NULL;
    }
    ret = mbedtls_md_setup(&ctx->ctx, md_info, 1);
    if (ret != 0)
    {
        os_free(ctx);
        return NULL;
    }
    mbedtls_md_hmac_starts(&ctx->ctx, key, key_len);

    return ctx;
}

void crypto_hash_update(struct crypto_hash *ctx, const u8 *data, size_t len)
{
    if (ctx == NULL)
    {
        return;
    }
    mbedtls_md_hmac_update(&ctx->ctx, data, len);
}

int crypto_hash_finish(struct crypto_hash *ctx, u8 *mac, size_t *len)
{
    if (ctx == NULL)
    {
        return -2;
    }

    if (mac == NULL || len == NULL)
    {
        mbedtls_md_free(&ctx->ctx);
        bin_clear_free(ctx, sizeof(*ctx));
        return 0;
    }
    mbedtls_md_hmac_finish(&ctx->ctx, mac);
    mbedtls_md_free(&ctx->ctx);
    bin_clear_free(ctx, sizeof(*ctx));

    return 0;
}

__attribute_noinline__ static int hmac_vector(const u8 *key,
                                              size_t key_len,
                                              size_t num_elem,
                                              const u8 *addr[],
                                              const size_t *len,
                                              u8 *mac,
                                              mbedtls_md_type_t md_type)
{
    return hmac_vector_psa(key, key_len, num_elem, addr, len, mac, md_type);
}

int hmac_sha512_vector(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return hmac_vector(key, key_len, num_elem, addr, len, mac, MBEDTLS_MD_SHA512);
}

int hmac_sha512(const u8 *key, size_t key_len, const u8 *data, size_t data_len, u8 *mac)
{
    return hmac_vector(key, key_len, 1, &data, &data_len, mac, MBEDTLS_MD_SHA512);
}

int hmac_sha384_vector(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return hmac_vector(key, key_len, num_elem, addr, len, mac, MBEDTLS_MD_SHA384);
}

int hmac_sha384(const u8 *key, size_t key_len, const u8 *data, size_t data_len, u8 *mac)
{
    return hmac_vector(key, key_len, 1, &data, &data_len, mac, MBEDTLS_MD_SHA384);
}

int hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return hmac_vector(key, key_len, num_elem, addr, len, mac, MBEDTLS_MD_SHA256);
}

int hmac_sha256(const u8 *key, size_t key_len, const u8 *data, size_t data_len, u8 *mac)
{
    return hmac_vector(key, key_len, 1, &data, &data_len, mac, MBEDTLS_MD_SHA256);
}

#if defined(CONFIG_PSA_WANT_ALG_SHA_1)
int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return hmac_vector(key, key_len, num_elem, addr, len, mac, MBEDTLS_MD_SHA1);
}

int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len, u8 *mac)
{
    return hmac_vector(key, key_len, 1, &data, &data_len, mac, MBEDTLS_MD_SHA1);
}
#endif

#if defined(CONFIG_PSA_WANT_ALG_MD5)
int hmac_md5_vector(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return hmac_vector(key, key_len, num_elem, addr, len, mac, MBEDTLS_MD_MD5);
}

int hmac_md5(const u8 *key, size_t key_len, const u8 *data, size_t data_len, u8 *mac)
{
    return hmac_vector(key, key_len, 1, &data, &data_len, mac, MBEDTLS_MD_MD5);
}
#endif

#if defined(PSA_WANT_ALG_HKDF)
#include <psa/crypto.h>

/* Perform "_op_" PSA API call and check if it succeeded. If not return
 * "_ret_fail_".
 * Note that operations using "psa_status" can be specified as second argument
 * like "do_something(psa_status)".
*/
#define PSA_CHECK(_op_, _ret_fail_) \
    do { \
        psa_status_t psa_status; \
        psa_status = _op_; \
        if (psa_status != PSA_SUCCESS) { \
            return _ret_fail_; \
        } \
    } while(0)
/* sha256-kdf.c sha384-kdf.c sha512-kdf.c */

/* HMAC-SHA256 KDF (RFC 5295) and HKDF-Expand(SHA256) (RFC 5869) */
/* HMAC-SHA384 KDF (RFC 5295) and HKDF-Expand(SHA384) (RFC 5869) */
/* HMAC-SHA512 KDF (RFC 5295) and HKDF-Expand(SHA512) (RFC 5869) */
__attribute_noinline__ static int hmac_kdf_expand(const u8 *prk,
                                                  size_t prk_len,
                                                  const char *label,
                                                  const u8 *info,
                                                  size_t info_len,
                                                  u8 *okm,
                                                  size_t okm_len,
                                                  mbedtls_md_type_t md_type)
{
    if (TEST_FAIL())
        return -1;

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    /* RFC 5869 HKDF-Expand when (label == NULL) */
    if (label == NULL) {
        psa_key_derivation_operation_t psa_op = PSA_KEY_DERIVATION_OPERATION_INIT;
        psa_algorithm_t psa_hash_alg = mbedtls_md_psa_alg_from_type(md_type);

        PSA_CHECK(psa_key_derivation_setup(&psa_op, PSA_ALG_HKDF_EXPAND(psa_hash_alg)), -1);
        PSA_CHECK(psa_key_derivation_input_bytes(&psa_op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                                 prk, prk_len), -1);
        PSA_CHECK(psa_key_derivation_input_bytes(&psa_op, PSA_KEY_DERIVATION_INPUT_INFO,
                                                 info, info_len), -1);
        PSA_CHECK(psa_key_derivation_output_bytes(&psa_op, okm, okm_len), -1);
        PSA_CHECK(psa_key_derivation_abort(&psa_op), -1);
    }

    const size_t mac_len = mbedtls_md_get_size(md_info);
    /* okm_len must not exceed 255 times hash len (RFC 5869 Section 2.3) */
    if (okm_len > ((mac_len << 8) - mac_len))
        return -1;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md_info, 0) != 0) {
        return -1;
    }
    if (mbedtls_md_hmac_setup(&ctx, md_info) != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }
    if (mbedtls_md_hmac_starts(&ctx, prk, prk_len) != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }

    u8 iter           = 1;
    const u8 *addr[4] = {okm, (const u8 *)label, info, &iter};
    size_t len[4]     = {0, label ? os_strlen(label) + 1 : 0, info_len, 1};

    for (; okm_len >= mac_len; okm_len -= mac_len, ++iter)
    {
        for (size_t i = 0; i < ARRAY_SIZE(addr); ++i)
            mbedtls_md_hmac_update(&ctx, addr[i], len[i]);
        mbedtls_md_hmac_finish(&ctx, okm);
        mbedtls_md_hmac_reset(&ctx);
        addr[0] = okm;
        okm += mac_len;
        len[0] = mac_len; /*(include digest in subsequent rounds)*/
    }

    if (okm_len)
    {
        u8 hash[MBEDTLS_MD_MAX_SIZE];
        for (size_t i = 0; i < ARRAY_SIZE(addr); ++i)
            mbedtls_md_hmac_update(&ctx, addr[i], len[i]);
        mbedtls_md_hmac_finish(&ctx, hash);
        os_memcpy(okm, hash, okm_len);
        forced_memzero(hash, mac_len);
    }

    mbedtls_md_free(&ctx);
    return 0;
}

int hmac_sha512_kdf(
    const u8 *secret, size_t secret_len, const char *label, const u8 *seed, size_t seed_len, u8 *out, size_t outlen)
{
    return hmac_kdf_expand(secret, secret_len, label, seed, seed_len, out, outlen, MBEDTLS_MD_SHA512);
}

int hmac_sha384_kdf(
    const u8 *secret, size_t secret_len, const char *label, const u8 *seed, size_t seed_len, u8 *out, size_t outlen)
{
    return hmac_kdf_expand(secret, secret_len, label, seed, seed_len, out, outlen, MBEDTLS_MD_SHA384);
}

int hmac_sha256_kdf(
    const u8 *secret, size_t secret_len, const char *label, const u8 *seed, size_t seed_len, u8 *out, size_t outlen)
{
    return hmac_kdf_expand(secret, secret_len, label, seed, seed_len, out, outlen, MBEDTLS_MD_SHA256);
}
#endif /* PSA_WANT_ALG_HKDF */

/* sha256-prf.c sha384-prf.c sha512-prf.c */

/* hmac_prf_bits - IEEE Std 802.11ac-2013, 11.6.1.7.2 Key derivation function */
__attribute_noinline__ static int hmac_prf_bits(const u8 *key,
                                                size_t key_len,
                                                const char *label,
                                                const u8 *data,
                                                size_t data_len,
                                                u8 *buf,
                                                size_t buf_len_bits,
                                                mbedtls_md_type_t md_type)
{
    if (TEST_FAIL())
        return -1;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (mbedtls_md_setup(&ctx, md_info, 1) != 0)
    {
        mbedtls_md_free(&ctx);
        return -1;
    }
    mbedtls_md_hmac_starts(&ctx, key, key_len);

    u16 ctr, n_le = host_to_le16(buf_len_bits);
    const u8 *const addr[] = {(u8 *)&ctr, (u8 *)label, data, (u8 *)&n_le};
    const size_t len[]     = {2, os_strlen(label), data_len, 2};
    const size_t mac_len   = mbedtls_md_get_size(md_info);
    size_t buf_len         = (buf_len_bits + 7) / 8;
    for (ctr = 1; buf_len >= mac_len; buf_len -= mac_len, ++ctr)
    {
#if __BYTE_ORDER == __BIG_ENDIAN
        ctr = host_to_le16(ctr);
#endif
        for (size_t i = 0; i < ARRAY_SIZE(addr); ++i)
            mbedtls_md_hmac_update(&ctx, addr[i], len[i]);
        mbedtls_md_hmac_finish(&ctx, buf);
        mbedtls_md_hmac_reset(&ctx);
        buf += mac_len;
#if __BYTE_ORDER == __BIG_ENDIAN
        ctr = le_to_host16(ctr);
#endif
    }

    if (buf_len)
    {
        u8 hash[MBEDTLS_MD_MAX_SIZE];
#if __BYTE_ORDER == __BIG_ENDIAN
        ctr = host_to_le16(ctr);
#endif
        for (size_t i = 0; i < ARRAY_SIZE(addr); ++i)
            mbedtls_md_hmac_update(&ctx, addr[i], len[i]);
        mbedtls_md_hmac_finish(&ctx, hash);
        os_memcpy(buf, hash, buf_len);
        buf += buf_len;
        forced_memzero(hash, mac_len);
    }

    /* Mask out unused bits in last octet if it does not use all the bits */
    if ((buf_len_bits &= 0x7))
        buf[-1] &= (u8)(0xff << (8 - buf_len_bits));

    mbedtls_md_free(&ctx);
    return 0;
}

int sha512_prf(
    const u8 *key, size_t key_len, const char *label, const u8 *data, size_t data_len, u8 *buf, size_t buf_len)
{
    return hmac_prf_bits(key, key_len, label, data, data_len, buf, buf_len * 8, MBEDTLS_MD_SHA512);
}

int sha384_prf(
    const u8 *key, size_t key_len, const char *label, const u8 *data, size_t data_len, u8 *buf, size_t buf_len)
{
    return hmac_prf_bits(key, key_len, label, data, data_len, buf, buf_len * 8, MBEDTLS_MD_SHA384);
}

/**
 * Based on Supplicant internal implementaion of SHA-256. This API
 * uses PSA APIs instead of Supplicant internal implementation or
 * mbedtls APIs.
 */
static int hmac_prf256(const u8 *key,
                       size_t key_len,
                       const char *label,
                       const u8 *data,
                       size_t data_len,
                       u8 *buf_in,
                       size_t buf_len_bits,
                       mbedtls_md_type_t md_type)
{
    unsigned short ctr, n_le = host_to_le16(buf_len_bits);
    const u8 *addr[]         = {(u8 *)&ctr, (u8 *)label, data, (u8 *)&n_le};
    const size_t len[]       = {2, os_strlen(label), data_len, 2};
    size_t buf_len           = (buf_len_bits + 7) / 8;
    u8 *buf  = buf_in;

    for (ctr = 1; buf_len >= SHA256_MAC_LEN; buf_len -= SHA256_MAC_LEN, ++ctr)
    {
            if (hmac_sha256_vector(key, key_len, 4, addr, len, buf))
                    return -1;
            buf += SHA256_MAC_LEN;
    }

    if (buf_len)
    {
            u8 hash[SHA256_MAC_LEN];
            if (hmac_sha256_vector(key, key_len, 4, addr, len, hash))
                    return -1;
            os_memcpy(buf, hash, buf_len);
            forced_memzero(hash, sizeof(hash));
    }

    /* Mask out unused bits in last octet if it does not use all the bits */
    if ((buf_len_bits &= 0x7))
            buf[-1] &= (u8)(0xff << (8 - buf_len_bits));

    return 0;
}

int sha256_prf(
    const u8 *key, size_t key_len, const char *label, const u8 *data, size_t data_len, u8 *buf, size_t buf_len)
{
    return hmac_prf256(key, key_len, label, data, data_len, buf, buf_len * 8, MBEDTLS_MD_SHA256);
}

int sha256_prf_bits(
    const u8 *key, size_t key_len, const char *label, const u8 *data, size_t data_len, u8 *buf, size_t buf_len_bits)
{
    return hmac_prf_bits(key, key_len, label, data, data_len, buf, buf_len_bits, MBEDTLS_MD_SHA256);
}

#if defined(CONFIG_PSA_WANT_ALG_SHA_1)

/* sha1-prf.c */

/* sha1_prf - SHA1-based Pseudo-Random Function (PRF) (IEEE 802.11i, 8.5.1.1) */

int sha1_prf(const u8 *key, size_t key_len, const char *label, const u8 *data, size_t data_len, u8 *buf, size_t buf_len)
{
    /*(note: algorithm differs from hmac_prf_bits() */
    /*(note: smaller code size instead of expanding hmac_sha1_vector()
     * as is done in hmac_prf_bits(); not expecting large num of loops) */
    u8 counter         = 0;
    const u8 *addr[]   = {(u8 *)label, data, &counter};
    const size_t len[] = {os_strlen(label) + 1, data_len, 1};

    for (; buf_len >= SHA1_MAC_LEN; buf_len -= SHA1_MAC_LEN, ++counter)
    {
        if (hmac_sha1_vector(key, key_len, 3, addr, len, buf))
            return -1;
        buf += SHA1_MAC_LEN;
    }

    if (buf_len)
    {
        u8 hash[SHA1_MAC_LEN];
        if (hmac_sha1_vector(key, key_len, 3, addr, len, hash))
            return -1;
        os_memcpy(buf, hash, buf_len);
        forced_memzero(hash, sizeof(hash));
    }

    return 0;
}

#ifdef CRYPTO_MBEDTLS_SHA1_T_PRF

/* sha1-tprf.c */

/* sha1_t_prf - EAP-FAST Pseudo-Random Function (T-PRF) (RFC 4851,Section 5.5)*/

int sha1_t_prf(
    const u8 *key, size_t key_len, const char *label, const u8 *seed, size_t seed_len, u8 *buf, size_t buf_len)
{
    /*(note: algorithm differs from hmac_prf_bits() and hmac_kdf() above)*/
    /*(note: smaller code size instead of expanding hmac_sha1_vector()
     * as is done in hmac_prf_bits(); not expecting large num of loops) */
    u8 ctr;
    u16 olen         = host_to_be16(buf_len);
    const u8 *addr[] = {buf, (u8 *)label, seed, (u8 *)&olen, &ctr};
    size_t len[]     = {0, os_strlen(label) + 1, seed_len, 2, 1};

    for (ctr = 1; buf_len >= SHA1_MAC_LEN; buf_len -= SHA1_MAC_LEN, ++ctr)
    {
        if (hmac_sha1_vector(key, key_len, 5, addr, len, buf))
            return -1;
        addr[0] = buf;
        buf += SHA1_MAC_LEN;
        len[0] = SHA1_MAC_LEN; /*(include digest in subsequent rounds)*/
    }

    if (buf_len)
    {
        u8 hash[SHA1_MAC_LEN];
        if (hmac_sha1_vector(key, key_len, 5, addr, len, hash))
            return -1;
        os_memcpy(buf, hash, buf_len);
        forced_memzero(hash, sizeof(hash));
    }

    return 0;
}

#endif /* CRYPTO_MBEDTLS_SHA1_T_PRF */
#endif /* CONFIG_PSA_WANT_ALG_SHA_1 */

#ifdef MBEDTLS_DES_C
#include <mbedtls/des.h>
int des_encrypt(const u8 *clear, const u8 *key, u8 *cypher)
{
    u8 pkey[8], next, tmp;
    int i;

    /* Add parity bits to the key */
    next = 0;
    for (i = 0; i < 7; i++)
    {
        tmp     = key[i];
        pkey[i] = (tmp >> i) | next | 1;
        next    = tmp << (7 - i);
    }
    pkey[i] = next | 1;

    mbedtls_des_context des;
    mbedtls_des_init(&des);
    int ret = mbedtls_des_setkey_enc(&des, pkey) || mbedtls_des_crypt_ecb(&des, clear, cypher) ? -1 : 0;
    mbedtls_des_free(&des);
    return ret;
}
#endif

#ifdef CRYPTO_MBEDTLS_PBKDF2_SHA1
/* sha1-pbkdf2.c */
#include <mbedtls/pkcs5.h>
int pbkdf2_sha1(const char *passphrase, const u8 *ssid, size_t ssid_len, int iterations, u8 *buf, size_t buflen)
{
    return pbkdf2_sha1_psa(MBEDTLS_MD_SHA1, (const u8 *)passphrase,
                           os_strlen(passphrase), ssid, ssid_len,
                           iterations, 32, buf) ? -1: 0;
}
#endif

#include "aes_wrap.h"

#ifdef MBEDTLS_NIST_KW_C

#include <mbedtls/nist_kw.h>
#include <psa/crypto.h>

/* aes-wrap.c */
int aes_wrap(const u8 *kek, size_t kek_len, int n, const u8 *plain, u8 *cipher)
{
    if (TEST_FAIL())
        return -1;

    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    size_t olen;
    psa_status_t status;
    int ret;

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECB_NO_PADDING);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&key_attr, kek, kek_len, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    ret = mbedtls_nist_kw_wrap(key_id, MBEDTLS_KW_MODE_KW, plain, n * 8, cipher, (n + 1) * 8, &olen);

    psa_reset_key_attributes(&key_attr);
    psa_destroy_key(key_id);

    return (ret != 0) ? -1 : 0;
}

/* aes-unwrap.c */
int aes_unwrap(const u8 *kek, size_t kek_len, int n, const u8 *cipher, u8 *plain)
{
    if (TEST_FAIL())
        return -1;

    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    size_t olen;
    psa_status_t status;
    int ret;

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECB_NO_PADDING);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&key_attr, kek, kek_len, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    ret = mbedtls_nist_kw_unwrap(key_id, MBEDTLS_KW_MODE_KW, cipher, (n + 1) * 8, plain, n * 8, &olen);

    psa_reset_key_attributes(&key_attr);
    psa_destroy_key(key_id);

    return (ret != 0) ? -1 : 0;
}
#endif /* MBEDTLS_NIST_KW_C */

#if defined(CONFIG_PSA_WANT_ALG_CMAC)

/* aes-omac1.c */

#include <mbedtls/cmac.h>

int omac1_aes_vector(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return omac1_aes_vector_psa(key, key_len, num_elem, addr, len, mac);
}

int omac1_aes_128_vector(const u8 *key, size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    return omac1_aes_vector(key, 16, num_elem, addr, len, mac);
}

int omac1_aes_128(const u8 *key, const u8 *data, size_t data_len, u8 *mac)
{
    return omac1_aes_vector(key, 16, 1, &data, &data_len, mac);
}

int omac1_aes_256(const u8 *key, const u8 *data, size_t data_len, u8 *mac)
{
    return omac1_aes_vector(key, 32, 1, &data, &data_len, mac);
}

#else

//#include "aes-omac1.c" /* pull in hostap local implementation */

#ifndef MBEDTLS_AES_BLOCK_SIZE
#define MBEDTLS_AES_BLOCK_SIZE 16
#endif

#endif /* CONFIG_PSA_WANT_ALG_CMAC */

#if defined(CONFIG_PSA_WANT_KEY_TYPE_AES)

/* These interfaces can be inefficient when used in loops, as the overhead of
 * initialization each call is large for each block input (e.g. 16 bytes) */

/* aes-encblock.c */
int aes_128_encrypt_block(const u8 *key, const u8 *in, u8 *out)
{
    return aes_128_encrypt_block_psa(key, in, out);
}

/* aes-ctr.c */
int aes_ctr_encrypt(const u8 *key, size_t key_len, const u8 *nonce, u8 *data, size_t data_len)
{
    return aes_ctr_encrypt_psa(key, key_len, nonce, data, data_len);
}

int aes_128_ctr_encrypt(const u8 *key, const u8 *nonce, u8 *data, size_t data_len)
{
    return aes_ctr_encrypt(key, 16, nonce, data, data_len);
}

#define HOSTAP_AES_ENCRYPT     0
#define HOSTAP_AES_DECRYPT     1

/* aes-cbc.c */
static int aes_128_cbc_oper(const u8 *key, const u8 *iv, u8 *data, size_t data_len, int mode)
{
    if (mode == HOSTAP_AES_ENCRYPT)
        return aes_128_cbc_encrypt_psa(key, iv, data, data_len);
    else
        return aes_128_cbc_decrypt_psa(key, iv, data, data_len);
}

int aes_128_cbc_encrypt(const u8 *key, const u8 *iv, u8 *data, size_t data_len)
{
    if (TEST_FAIL())
        return -1;

    return aes_128_cbc_oper(key, iv, data, data_len, HOSTAP_AES_ENCRYPT);
}

int aes_128_cbc_decrypt(const u8 *key, const u8 *iv, u8 *data, size_t data_len)
{
    if (TEST_FAIL())
        return -1;

    return aes_128_cbc_oper(key, iv, data, data_len, HOSTAP_AES_DECRYPT);
}
#endif /* CONFIG_PSA_WANT_KEY_TYPE_AES */

/*
 * Much of the following is documented in crypto.h as for CONFIG_TLS=internal
 * but such comments are not accurate:
 *
 * "This function is only used with internal TLSv1 implementation
 *  (CONFIG_TLS=internal). If that is not used, the crypto wrapper does not need
 *  to implement this."
 */

#ifdef CRYPTO_MBEDTLS_CRYPTO_CIPHER

#include <mbedtls/cipher.h>

struct crypto_cipher
{
    mbedtls_cipher_context_t ctx_enc;
    mbedtls_cipher_context_t ctx_dec;
};

struct crypto_cipher *crypto_cipher_init(enum crypto_cipher_alg alg, const u8 *iv, const u8 *key, size_t key_len)
{
    /* IKEv2 src/eap_common/ikev2_common.c:ikev2_{encr,decr}_encrypt()
     * uses one of CRYPTO_CIPHER_ALG_AES or CRYPTO_CIPHER_ALG_3DES */

    mbedtls_cipher_type_t cipher_type;
    size_t iv_len;
    switch (alg)
    {
#ifdef PSA_WANT_KEY_TYPE_AES
        case CRYPTO_CIPHER_ALG_AES:
            if (key_len == 16)
                cipher_type = MBEDTLS_CIPHER_AES_128_CTR;
            if (key_len == 24)
                cipher_type = MBEDTLS_CIPHER_AES_192_CTR;
            if (key_len == 32)
                cipher_type = MBEDTLS_CIPHER_AES_256_CTR;
            iv_len = 16;
            break;
#endif
        default:
            return NULL;
    }

    const mbedtls_cipher_info_t *cipher_info;
    cipher_info = mbedtls_cipher_info_from_type(cipher_type);
    if (cipher_info == NULL)
        return NULL;

    key_len *= 8;                        /* key_bitlen */

    struct crypto_cipher *ctx = os_malloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    mbedtls_cipher_init(&ctx->ctx_enc);
    mbedtls_cipher_init(&ctx->ctx_dec);
    if (mbedtls_cipher_setup(&ctx->ctx_enc, cipher_info) == 0 &&
        mbedtls_cipher_setup(&ctx->ctx_dec, cipher_info) == 0 &&
        mbedtls_cipher_setkey(&ctx->ctx_enc, key, key_len, MBEDTLS_ENCRYPT) == 0 &&
        mbedtls_cipher_setkey(&ctx->ctx_dec, key, key_len, MBEDTLS_DECRYPT) == 0 &&
        mbedtls_cipher_set_iv(&ctx->ctx_enc, iv, iv_len) == 0 &&
        mbedtls_cipher_set_iv(&ctx->ctx_dec, iv, iv_len) == 0 && mbedtls_cipher_reset(&ctx->ctx_enc) == 0 &&
        mbedtls_cipher_reset(&ctx->ctx_dec) == 0)
    {
        return ctx;
    }

    mbedtls_cipher_free(&ctx->ctx_enc);
    mbedtls_cipher_free(&ctx->ctx_dec);
    os_free(ctx);
    return NULL;
}

int crypto_cipher_encrypt(struct crypto_cipher *ctx, const u8 *plain, u8 *crypt, size_t len)
{
    size_t olen = 0; /*(poor interface above; unknown size of u8 *crypt)*/
    return (mbedtls_cipher_update(&ctx->ctx_enc, plain, len, crypt, &olen) ||
            mbedtls_cipher_finish(&ctx->ctx_enc, crypt + olen, &olen)) ?
               -1 :
               0;
}

int crypto_cipher_decrypt(struct crypto_cipher *ctx, const u8 *crypt, u8 *plain, size_t len)
{
    size_t olen = 0; /*(poor interface above; unknown size of u8 *plain)*/
    return (mbedtls_cipher_update(&ctx->ctx_dec, crypt, len, plain, &olen) ||
            mbedtls_cipher_finish(&ctx->ctx_dec, plain + olen, &olen)) ?
               -1 :
               0;
}

void crypto_cipher_deinit(struct crypto_cipher *ctx)
{
    mbedtls_cipher_free(&ctx->ctx_enc);
    mbedtls_cipher_free(&ctx->ctx_dec);
    os_free(ctx);
}

#endif /* CRYPTO_MBEDTLS_CRYPTO_CIPHER */

#ifdef CRYPTO_MBEDTLS_CRYPTO_BIGNUM

#include <mbedtls/bignum.h>

/* crypto.h bignum interfaces */

struct crypto_bignum *crypto_bignum_init(void)
{
    if (TEST_FAIL())
        return NULL;

    mbedtls_mpi *bn = os_malloc(sizeof(*bn));
    if (bn)
        mbedtls_mpi_init(bn);
    return (struct crypto_bignum *)bn;
}

struct crypto_bignum *crypto_bignum_init_set(const u8 *buf, size_t len)
{
    if (TEST_FAIL())
        return NULL;

    mbedtls_mpi *bn = os_malloc(sizeof(*bn));
    if (bn)
    {
        mbedtls_mpi_init(bn);
        if (mbedtls_mpi_read_binary(bn, buf, len) == 0)
            return (struct crypto_bignum *)bn;
    }

    os_free(bn);
    return NULL;
}

struct crypto_bignum *crypto_bignum_init_uint(unsigned int val)
{
    if (TEST_FAIL())
        return NULL;

    mbedtls_mpi *bn = os_malloc(sizeof(*bn));
    if (bn)
    {
        mbedtls_mpi_init(bn);
        if (mbedtls_mpi_lset(bn, (int)val) == 0)
            return (struct crypto_bignum *)bn;
    }

    os_free(bn);
    return NULL;
}

void crypto_bignum_deinit(struct crypto_bignum *n, int clear)
{
    mbedtls_mpi_free((mbedtls_mpi *)n);
    os_free(n);
}

int crypto_bignum_to_bin(const struct crypto_bignum *a, u8 *buf, size_t buflen, size_t padlen)
{
    if (TEST_FAIL())
        return -1;

    size_t n = mbedtls_mpi_size((mbedtls_mpi *)a);
    if (n < padlen)
        n = padlen;
    return n > buflen || mbedtls_mpi_write_binary((mbedtls_mpi *)a, buf, n) ? -1 : (int)(n);
}

int crypto_bignum_rand(struct crypto_bignum *r, const struct crypto_bignum *m)
{
    if (TEST_FAIL())
        return -1;

        /*assert(r != m);*/              /* r must not be same as m for mbedtls_mpi_random()*/
    return mbedtls_mpi_random((mbedtls_mpi *)r, 0, (mbedtls_mpi *)m, hostap_rng_fn, hostap_rng_ctx()) ?
               -1 :
               0;
}

int crypto_bignum_add(const struct crypto_bignum *a, const struct crypto_bignum *b, struct crypto_bignum *c)
{
    return mbedtls_mpi_add_mpi((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ? -1 : 0;
}

int crypto_bignum_mod(const struct crypto_bignum *a, const struct crypto_bignum *b, struct crypto_bignum *c)
{
    return mbedtls_mpi_mod_mpi((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ? -1 : 0;
}

int crypto_bignum_exptmod(const struct crypto_bignum *a,
                          const struct crypto_bignum *b,
                          const struct crypto_bignum *c,
                          struct crypto_bignum *d)
{
    if (TEST_FAIL())
        return -1;

    /* (check if input params match d; d is the result) */
    /* (a == d) is ok in current mbedtls implementation */
    if (b == d || c == d)
    { /*(not ok; store result in intermediate)*/
        mbedtls_mpi R;
        mbedtls_mpi_init(&R);
        int rc =
            mbedtls_mpi_exp_mod(&R, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b, (const mbedtls_mpi *)c, NULL) ||
                    mbedtls_mpi_copy((mbedtls_mpi *)d, &R) ?
                -1 :
                0;
        mbedtls_mpi_free(&R);
        return rc;
    }
    else
    {
        return mbedtls_mpi_exp_mod((mbedtls_mpi *)d, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b,
                                   (const mbedtls_mpi *)c, NULL) ?
                   -1 :
                   0;
    }
}

int crypto_bignum_inverse(const struct crypto_bignum *a, const struct crypto_bignum *b, struct crypto_bignum *c)
{
    if (TEST_FAIL())
        return -1;

    return mbedtls_mpi_inv_mod((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ? -1 : 0;
}

int crypto_bignum_sub(const struct crypto_bignum *a, const struct crypto_bignum *b, struct crypto_bignum *c)
{
    if (TEST_FAIL())
        return -1;

    return mbedtls_mpi_sub_mpi((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ? -1 : 0;
}

int crypto_bignum_div(const struct crypto_bignum *a, const struct crypto_bignum *b, struct crypto_bignum *c)
{
    if (TEST_FAIL())
        return -1;

    /*(most current use of this crypto.h interface has a == c (result),
     * so store result in an intermediate to avoid overwritten input)*/
    mbedtls_mpi R;
    mbedtls_mpi_init(&R);
    int rc = mbedtls_mpi_div_mpi(&R, NULL, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ||
                     mbedtls_mpi_copy((mbedtls_mpi *)c, &R) ?
                 -1 :
                 0;
    mbedtls_mpi_free(&R);
    return rc;
}

int crypto_bignum_addmod(const struct crypto_bignum *a,
                         const struct crypto_bignum *b,
                         const struct crypto_bignum *c,
                         struct crypto_bignum *d)
{
    if (TEST_FAIL())
        return -1;

    return mbedtls_mpi_add_mpi((mbedtls_mpi *)d, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ||
                   mbedtls_mpi_mod_mpi((mbedtls_mpi *)d, (mbedtls_mpi *)d, (const mbedtls_mpi *)c) ?
               -1 :
               0;
}

int crypto_bignum_mulmod(const struct crypto_bignum *a,
                         const struct crypto_bignum *b,
                         const struct crypto_bignum *c,
                         struct crypto_bignum *d)
{
    if (TEST_FAIL())
        return -1;

    return mbedtls_mpi_mul_mpi((mbedtls_mpi *)d, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ||
                   mbedtls_mpi_mod_mpi((mbedtls_mpi *)d, (mbedtls_mpi *)d, (const mbedtls_mpi *)c) ?
               -1 :
               0;
}

int crypto_bignum_sqrmod(const struct crypto_bignum *a, const struct crypto_bignum *b, struct crypto_bignum *c)
{
    if (TEST_FAIL())
        return -1;

#if 1
    return crypto_bignum_mulmod(a, a, b, c);
#else
    mbedtls_mpi bn;
    mbedtls_mpi_init(&bn);
    if (mbedtls_mpi_lset(&bn, 2)) /* alt?: mbedtls_mpi_set_bit(&bn, 1) */
        return -1;
    int ret = mbedtls_mpi_exp_mod((mbedtls_mpi *)c, (const mbedtls_mpi *)a, &bn, (const mbedtls_mpi *)b, NULL) ? -1 : 0;
    mbedtls_mpi_free(&bn);
    return ret;
#endif
}

int crypto_bignum_rshift(const struct crypto_bignum *a, int n, struct crypto_bignum *r)
{
    return mbedtls_mpi_copy((mbedtls_mpi *)r, (const mbedtls_mpi *)a) || mbedtls_mpi_shift_r((mbedtls_mpi *)r, n) ? -1 :
                                                                                                                    0;
}

int crypto_bignum_cmp(const struct crypto_bignum *a, const struct crypto_bignum *b)
{
    return mbedtls_mpi_cmp_mpi((const mbedtls_mpi *)a, (const mbedtls_mpi *)b);
}

int crypto_bignum_is_zero(const struct crypto_bignum *a)
{
    /* XXX: src/common/sae.c:sswu() contains comment:
     * "TODO: Make sure crypto_bignum_is_zero() is constant time"
     * Note: mbedtls_mpi_cmp_int() *is not* constant time */
    return (mbedtls_mpi_cmp_int((const mbedtls_mpi *)a, 0) == 0);
}

int crypto_bignum_is_one(const struct crypto_bignum *a)
{
    return (mbedtls_mpi_cmp_int((const mbedtls_mpi *)a, 1) == 0);
}

int crypto_bignum_is_odd(const struct crypto_bignum *a)
{
    return mbedtls_mpi_get_bit((const mbedtls_mpi *)a, 0);
}

#include "utils/const_time.h"
int crypto_bignum_legendre(const struct crypto_bignum *a, const struct crypto_bignum *p)
{
    if (TEST_FAIL())
        return -2;

    /* Security Note:
     * mbedtls_mpi_exp_mod() is not documented to run in constant time,
     * though mbedtls/library/bignum.c uses constant_time_internal.h funcs.
     * Compare to crypto_openssl.c:crypto_bignum_legendre()
     * which uses openssl BN_mod_exp_mont_consttime()
     * mbedtls/library/ecp.c has further countermeasures to timing attacks,
     * (but ecp.c funcs are not used here) */

    mbedtls_mpi exp, tmp;
    mbedtls_mpi_init(&exp);
    mbedtls_mpi_init(&tmp);

    /* exp = (p-1) / 2 */
    int res;
    if (mbedtls_mpi_sub_int(&exp, (const mbedtls_mpi *)p, 1) == 0 && mbedtls_mpi_shift_r(&exp, 1) == 0 &&
        mbedtls_mpi_exp_mod(&tmp, (const mbedtls_mpi *)a, &exp, (const mbedtls_mpi *)p, NULL) == 0)
    {
        /*(modified from crypto_openssl.c:crypto_bignum_legendre())*/
        /* Return 1 if tmp == 1, 0 if tmp == 0, or -1 otherwise. Need
         * to use constant time selection to avoid branches here. */
        unsigned int mask;
        res  = -1;
        mask = const_time_eq((mbedtls_mpi_cmp_int(&tmp, 1) == 0), 1);
        res  = const_time_select_int(mask, 1, res);
        mask = const_time_eq((mbedtls_mpi_cmp_int(&tmp, 0) == 0), 1);
        res  = const_time_select_int(mask, 0, res);
    }
    else
    {
        res = -2;
    }

    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&exp);
    return res;
}

#endif /* CRYPTO_MBEDTLS_CRYPTO_BIGNUM */

#ifdef CRYPTO_MBEDTLS_CRYPTO_DH

/* crypto_internal-modexp.c */

#include <mbedtls/bignum.h>
#include <mbedtls/dhm.h>

static int crypto_mbedtls_dh_set_bin_pg(mbedtls_dhm_context *ctx, u8 generator, const u8 *prime, size_t prime_len)
{
    /*(could set these directly in MBEDTLS_PRIVATE members)*/
    mbedtls_mpi P, G;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);
    int ret = mbedtls_mpi_lset(&G, generator) || mbedtls_mpi_read_binary(&P, prime, prime_len) ||
              mbedtls_dhm_set_group(ctx, &P, &G);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&G);
    return ret;
}

__attribute_noinline__ static int crypto_mbedtls_dh_init_public(
    mbedtls_dhm_context *ctx, u8 generator, const u8 *prime, size_t prime_len, u8 *privkey, u8 *pubkey)
{
    if (crypto_mbedtls_dh_set_bin_pg(ctx, generator, prime, prime_len) ||
        mbedtls_dhm_make_public(ctx, (int)prime_len, pubkey, prime_len, hostap_rng_fn, hostap_rng_ctx()))
        return -1;

    return mbedtls_mpi_write_binary(&ctx->MBEDTLS_PRIVATE(X), privkey, prime_len) ? -1 : 0;
}

int crypto_dh_init(u8 generator, const u8 *prime, size_t prime_len, u8 *privkey, u8 *pubkey)
{
    if (TEST_FAIL())
        return -1;

    /* Prefer to use mbedtls to derive our public/private key, as doing so
     * leverages mbedtls to properly format output and to perform blinding*/
    mbedtls_dhm_context ctx;
    mbedtls_dhm_init(&ctx);
    int ret = crypto_mbedtls_dh_init_public(&ctx, generator, prime, prime_len, privkey, pubkey);
    mbedtls_dhm_free(&ctx);
    return ret;
}

/*(crypto_dh_derive_secret() could be implemented using crypto.h APIs
 * instead of being reimplemented in each crypto_*.c)*/
int crypto_dh_derive_secret(u8 generator,
                            const u8 *prime,
                            size_t prime_len,
                            const u8 *order,
                            size_t order_len,
                            const u8 *privkey,
                            size_t privkey_len,
                            const u8 *pubkey,
                            size_t pubkey_len,
                            u8 *secret,
                            size_t *len)
{
    if (TEST_FAIL())
        return -1;

    /* Prefer to use mbedtls to derive DH shared secret, as doing so
     * leverages mbedtls to validate params and to perform blinding.
     *
     * Attempt to reconstitute DH context to derive shared secret
     * (due to limitations of the interface, which ought to pass context).
     * Force provided G (our private key) into context without validation.
     * Regenerating GX (our public key) not needed to derive shared secret.
     */
    /*(older compilers might not support VLAs)*/
    /*unsigned char buf[2+prime_len+2+1+2+pubkey_len];*/
    unsigned char buf[2 + MBEDTLS_MPI_MAX_SIZE + 2 + 1 + 2 + MBEDTLS_MPI_MAX_SIZE];
    unsigned char *p = buf + 2 + prime_len;
    if (2 + prime_len + 2 + 1 + 2 + pubkey_len > sizeof(buf))
        return -1;
    WPA_PUT_BE16(buf, prime_len); /*(2-byte big-endian size of prime)*/
    p[0] = 0;                     /*(2-byte big-endian size of generator)*/
    p[1] = 1;
    p[2] = generator;
    WPA_PUT_BE16(p + 3, pubkey_len); /*(2-byte big-endian size of pubkey)*/
    os_memcpy(p + 5, pubkey, pubkey_len);
    os_memcpy(buf + 2, prime, prime_len);

    mbedtls_dhm_context ctx;
    mbedtls_dhm_init(&ctx);
    p = buf;
    int ret =
        mbedtls_dhm_read_params(&ctx, &p, p + 2 + prime_len + 5 + pubkey_len) ||
                mbedtls_mpi_read_binary(&ctx.MBEDTLS_PRIVATE(X), privkey, privkey_len) ||
                mbedtls_dhm_calc_secret(&ctx, secret, *len, len, hostap_rng_fn, hostap_rng_ctx()) ?
            -1 :
            0;
    mbedtls_dhm_free(&ctx);
    return ret;
}

/* dh_group5.c */

#include "dh_group5.h"

/* RFC3526_PRIME_1536[] and RFC3526_GENERATOR_1536[] from crypto_wolfssl.c */

static const unsigned char RFC3526_PRIME_1536[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6,
    0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A,
    0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF,
    0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63,
    0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5,
    0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x23, 0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static const unsigned char RFC3526_GENERATOR_1536[] = {0x02};

void *dh5_init(struct wpabuf **priv, struct wpabuf **publ)
{
    const unsigned char *const prime = RFC3526_PRIME_1536;
    const size_t prime_len           = sizeof(RFC3526_PRIME_1536);
    const u8 generator               = *RFC3526_GENERATOR_1536;
    struct wpabuf *wpubl = NULL, *wpriv = NULL;

    mbedtls_dhm_context *ctx = os_malloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    mbedtls_dhm_init(ctx);

    if ((wpubl = wpabuf_alloc(prime_len)) && (wpriv = wpabuf_alloc(prime_len)) &&
        crypto_mbedtls_dh_init_public(ctx, generator, prime, prime_len, wpabuf_put(wpriv, prime_len),
                                      wpabuf_put(wpubl, prime_len)) == 0)
    {
        wpabuf_free(*publ);
        wpabuf_clear_free(*priv);
        *publ = wpubl;
        *priv = wpriv;
        return ctx;
    }

    wpabuf_clear_free(wpriv);
    wpabuf_free(wpubl);
    mbedtls_dhm_free(ctx);
    os_free(ctx);
    return NULL;
}

#ifdef CRYPTO_MBEDTLS_DH5_INIT_FIXED
void *dh5_init_fixed(const struct wpabuf *priv, const struct wpabuf *publ)
{
    const unsigned char *const prime = RFC3526_PRIME_1536;
    const size_t prime_len           = sizeof(RFC3526_PRIME_1536);
    const u8 generator               = *RFC3526_GENERATOR_1536;

    mbedtls_dhm_context *ctx = os_malloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    mbedtls_dhm_init(ctx);

    if (crypto_mbedtls_dh_set_bin_pg(ctx, generator, prime, prime_len) == 0
        && mbedtls_mpi_read_binary(&ctx->MBEDTLS_PRIVATE(X), wpabuf_head(priv), wpabuf_len(priv)) == 0)
    {
        return ctx;
    }

    mbedtls_dhm_free(ctx);
    os_free(ctx);
    return NULL;
}
#endif

struct wpabuf *dh5_derive_shared(void *ctx, const struct wpabuf *peer_public, const struct wpabuf *own_private)
{
    /*((mbedtls_dhm_context *)ctx must already contain own_private)*/
    /* mbedtls 2.x: prime_len = ctx->len; */
    /* mbedtls 3.x: prime_len = mbedtls_dhm_get_len(ctx); */
    size_t olen        = sizeof(RFC3526_PRIME_1536); /*(sizeof(); prime known)*/
    struct wpabuf *buf = wpabuf_alloc(olen);
    if (buf == NULL)
        return NULL;
    if (mbedtls_dhm_read_public((mbedtls_dhm_context *)ctx, wpabuf_head(peer_public), wpabuf_len(peer_public)) == 0 &&
        mbedtls_dhm_calc_secret(ctx, wpabuf_mhead(buf), olen, &olen, hostap_rng_fn, hostap_rng_ctx()) == 0)
    {
        wpabuf_put(buf, olen);
        return buf;
    }

    wpabuf_free(buf);
    return NULL;
}

void dh5_free(void *ctx)
{
    mbedtls_dhm_free(ctx);
    os_free(ctx);
}

#endif /* CRYPTO_MBEDTLS_CRYPTO_DH */

#if defined(CRYPTO_MBEDTLS_CRYPTO_ECDH) || defined(CRYPTO_MBEDTLS_CRYPTO_EC)

#include <mbedtls/ecp.h>

#define CRYPTO_EC_pbits(e) (((mbedtls_ecp_group *)(e))->pbits)
#define CRYPTO_EC_plen(e)  ((((mbedtls_ecp_group *)(e))->pbits + 7) >> 3)
#define CRYPTO_EC_P(e)     (&((mbedtls_ecp_group *)(e))->P)
#define CRYPTO_EC_N(e)     (&((mbedtls_ecp_group *)(e))->N)
#define CRYPTO_EC_A(e)     (&((mbedtls_ecp_group *)(e))->A)
#define CRYPTO_EC_B(e)     (&((mbedtls_ecp_group *)(e))->B)
#define CRYPTO_EC_G(e)     (&((mbedtls_ecp_group *)(e))->G)

static mbedtls_ecp_group_id crypto_mbedtls_ecp_group_id_from_ike_id(int group)
{
    /* https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml */
    switch (group)
    {
#ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
        case 19:
            return MBEDTLS_ECP_DP_SECP256R1;
#endif
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
        case 20:
            return MBEDTLS_ECP_DP_SECP384R1;
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
        case 21:
            return MBEDTLS_ECP_DP_SECP521R1;
#endif
#ifdef MBEDTLS_ECP_DP_SECP192R1_ENABLED
        case 25:
            return MBEDTLS_ECP_DP_SECP192R1;
#endif
#ifdef MBEDTLS_ECP_DP_SECP224R1_ENABLED
        case 26:
            return MBEDTLS_ECP_DP_SECP224R1;
#endif
#ifdef MBEDTLS_ECP_DP_BP256R1_ENABLED
        case 28:
            return MBEDTLS_ECP_DP_BP256R1;
#endif
#ifdef MBEDTLS_ECP_DP_BP384R1_ENABLED
        case 29:
            return MBEDTLS_ECP_DP_BP384R1;
#endif
#ifdef MBEDTLS_ECP_DP_BP512R1_ENABLED
        case 30:
            return MBEDTLS_ECP_DP_BP512R1;
#endif
#ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
        case 31:
            return MBEDTLS_ECP_DP_CURVE25519;
#endif
#ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
        case 32:
            return MBEDTLS_ECP_DP_CURVE448;
#endif
        default:
            return MBEDTLS_ECP_DP_NONE;
    }
}

#endif /* CRYPTO_MBEDTLS_CRYPTO_ECDH || CRYPTO_MBEDTLS_CRYPTO_EC */

#ifdef CRYPTO_MBEDTLS_CRYPTO_EC
static int crypto_mbedtls_ike_id_from_ecp_group_id(mbedtls_ecp_group_id grp_id)
{
    /* https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml */
    /*(for crypto_ec_key_group())*/
    switch (grp_id)
    {
#ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
        case MBEDTLS_ECP_DP_SECP256R1:
            return 19;
#endif
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
        case MBEDTLS_ECP_DP_SECP384R1:
            return 20;
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
        case MBEDTLS_ECP_DP_SECP521R1:
            return 21;
#endif
#ifdef MBEDTLS_ECP_DP_SECP192R1_ENABLED
        case MBEDTLS_ECP_DP_SECP192R1:
            return 25;
#endif
#ifdef MBEDTLS_ECP_DP_SECP224R1_ENABLED
        case MBEDTLS_ECP_DP_SECP224R1:
            return 26;
#endif
#ifdef MBEDTLS_ECP_DP_BP256R1_ENABLED
        case MBEDTLS_ECP_DP_BP256R1:
            return 28;
#endif
#ifdef MBEDTLS_ECP_DP_BP384R1_ENABLED
        case MBEDTLS_ECP_DP_BP384R1:
            return 29;
#endif
#ifdef MBEDTLS_ECP_DP_BP512R1_ENABLED
        case MBEDTLS_ECP_DP_BP512R1:
            return 30;
#endif
#ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
        case MBEDTLS_ECP_DP_CURVE25519:
            return 31;
#endif
#ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
        case MBEDTLS_ECP_DP_CURVE448:
            return 32;
#endif
        default:
            return -1;
    }
}

#endif /* CRYPTO_MBEDTLS_CRYPTO_EC */

#if defined(CRYPTO_MBEDTLS_CRYPTO_ECDH) || defined(CRYPTO_MBEDTLS_CRYPTO_EC_DPP)

#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>

/* tf-psa-crypto internal functions */
psa_ecc_family_t mbedtls_ecc_group_to_psa(mbedtls_ecp_group_id grpid, size_t *bits);
mbedtls_ecp_group_id mbedtls_ecc_group_from_psa(psa_ecc_family_t family, size_t bits);

static int crypto_mbedtls_keypair_gen(int group, psa_key_id_t *key_id)
{
    mbedtls_ecp_group_id grp_id = crypto_mbedtls_ecp_group_id_from_ike_id(group);
    psa_ecc_family_t ec_family;
    psa_key_bits_t key_bits;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;

    *key_id = PSA_KEY_ID_NULL;

    ec_family = mbedtls_ecc_group_to_psa(grp_id, (size_t *) &key_bits);
    if (ec_family == 0) {
        return -1;
    }

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(ec_family));
    psa_set_key_bits(&key_attr, key_bits);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE |
                            PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    if (psa_generate_key(&key_attr, key_id) != PSA_SUCCESS) {
        return -1;
    }

    return 0;
}

#endif

#ifdef CRYPTO_MBEDTLS_CRYPTO_ECDH

#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>

struct crypto_ecdh {
    mbedtls_pk_context our_key;
    uint8_t peer_key[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)];
    uint8_t shared_secret[PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS)];
};

/*
 * Following map is being used:
 *      struct crypto_ec_key --> mbedtls_pk_context
 */

struct crypto_ec {
    mbedtls_ecp_group group;
};

struct crypto_ecdh *crypto_ecdh_init(int group)
{
    struct crypto_ecdh *ecdh = NULL;
    psa_key_id_t key_id;
    int ret;

    if (crypto_mbedtls_keypair_gen(group, &key_id) != 0) {
        return NULL;
    }

    ecdh = os_calloc(sizeof(struct crypto_ecdh), 1);
    if (ecdh == NULL) {
        psa_destroy_key(key_id);
        return NULL;
    }

    mbedtls_pk_init(&ecdh->our_key);
    ret = mbedtls_pk_copy_from_psa(key_id, &ecdh->our_key);
    psa_destroy_key(key_id);
    if (ret != 0) {
        mbedtls_pk_free(&ecdh->our_key);
        os_free(ecdh);
        return NULL;
    }

    return ecdh;
}

struct crypto_ecdh *crypto_ecdh_init2(int group, struct crypto_ec_key *own_key)
{
    struct crypto_ecdh *ecdh = NULL;
    mbedtls_pk_context *pk = (mbedtls_pk_context *) own_key;

    ecdh = os_calloc(sizeof(struct crypto_ecdh), 1);
    if (ecdh == NULL) {
        return NULL;
    }

    memcpy(&ecdh->our_key, pk, sizeof(mbedtls_pk_context));

    return ecdh;
}

struct wpabuf *crypto_ecdh_get_pubkey(struct crypto_ecdh *ecdh, int inc_y)
{
    struct wpabuf *buf = wpabuf_alloc(PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS));
    if (buf == NULL) {
        return NULL;
    }

    if (mbedtls_pk_write_pubkey_der(&ecdh->our_key, wpabuf_mhead(buf), wpabuf_len(buf)) < 0) {
        wpabuf_free(buf);
        return NULL;
    }

    return buf;
}

struct wpabuf *crypto_ecdh_set_peerkey(struct crypto_ecdh *ecdh, int inc_y, const u8 *key, size_t len)
{
    struct wpabuf *buf;
    size_t olen;

    buf = wpabuf_alloc(sizeof(&ecdh->shared_secret));
    if (buf == NULL) {
        return NULL;
    }

    if (psa_raw_key_agreement(PSA_ALG_ECDH, ecdh->our_key.MBEDTLS_PRIVATE(priv_id),
                              key, len,
                              wpabuf_mhead(buf), wpabuf_len(buf), &olen) != 0) {
        wpabuf_free(buf);
        return NULL;
    }

    return buf;
}

void crypto_ecdh_deinit(struct crypto_ecdh *ecdh)
{
    if (ecdh == NULL)
        return;
    mbedtls_pk_free(&ecdh->our_key);
    os_free(ecdh);
}

size_t crypto_ecdh_prime_len(struct crypto_ecdh *ecdh)
{
    return mbedtls_pk_get_bitlen(&ecdh->our_key);
}

#endif /* CRYPTO_MBEDTLS_CRYPTO_ECDH */

#if defined(CRYPTO_MBEDTLS_CRYPTO_EC)

#include <mbedtls/ecp.h>

struct crypto_ec *crypto_ec_init(int group)
{
    mbedtls_ecp_group_id grp_id = crypto_mbedtls_ecp_group_id_from_ike_id(group);
    if (grp_id == MBEDTLS_ECP_DP_NONE)
        return NULL;
    mbedtls_ecp_group *e = os_malloc(sizeof(*e));
    if (e == NULL)
        return NULL;
    mbedtls_ecp_group_init(e);
    if (mbedtls_ecp_group_load(e, grp_id) == 0)
        return (struct crypto_ec *)e;

    mbedtls_ecp_group_free(e);
    os_free(e);
    return NULL;
}

void crypto_ec_deinit(struct crypto_ec *e)
{
    mbedtls_ecp_group_free((mbedtls_ecp_group *)e);
    os_free(e);
}

size_t crypto_ec_prime_len(struct crypto_ec *e)
{
    return CRYPTO_EC_plen(e);
}

size_t crypto_ec_prime_len_bits(struct crypto_ec *e)
{
    return CRYPTO_EC_pbits(e);
}

size_t crypto_ec_order_len(struct crypto_ec *e)
{
    return (mbedtls_mpi_bitlen(CRYPTO_EC_N(e)) + 7) / 8;
}

const struct crypto_bignum *crypto_ec_get_prime(struct crypto_ec *e)
{
    return (const struct crypto_bignum *)CRYPTO_EC_P(e);
}

const struct crypto_bignum *crypto_ec_get_order(struct crypto_ec *e)
{
    return (const struct crypto_bignum *)CRYPTO_EC_N(e);
}

const struct crypto_bignum *crypto_ec_get_a(struct crypto_ec *e)
{
#ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
    static const uint8_t secp256r1_a[] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};
#endif
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
    static const uint8_t secp384r1_a[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfc};
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
    static const uint8_t secp521r1_a[] = {
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};
#endif
#ifdef MBEDTLS_ECP_DP_SECP192R1_ENABLED
    static const uint8_t secp192r1_a[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};
#endif
#ifdef MBEDTLS_ECP_DP_SECP224R1_ENABLED
    static const uint8_t secp224r1_a[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe};
#endif

    const uint8_t *bin = NULL;
    size_t len         = 0;

    /* (mbedtls groups matching supported sswu_curve_param() IKE groups) */
    switch (((mbedtls_ecp_group *)e)->id)
    {
#ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
        case MBEDTLS_ECP_DP_SECP256R1:
            bin = secp256r1_a;
            len = sizeof(secp256r1_a);
            break;
#endif
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
        case MBEDTLS_ECP_DP_SECP384R1:
            bin = secp384r1_a;
            len = sizeof(secp384r1_a);
            break;
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
        case MBEDTLS_ECP_DP_SECP521R1:
            bin = secp521r1_a;
            len = sizeof(secp521r1_a);
            break;
#endif
#ifdef MBEDTLS_ECP_DP_SECP192R1_ENABLED
        case MBEDTLS_ECP_DP_SECP192R1:
            bin = secp192r1_a;
            len = sizeof(secp192r1_a);
            break;
#endif
#ifdef MBEDTLS_ECP_DP_SECP224R1_ENABLED
        case MBEDTLS_ECP_DP_SECP224R1:
            bin = secp224r1_a;
            len = sizeof(secp224r1_a);
            break;
#endif
#ifdef MBEDTLS_ECP_DP_BP256R1_ENABLED
        case MBEDTLS_ECP_DP_BP256R1:
            return (const struct crypto_bignum *)CRYPTO_EC_A(e);
#endif
#ifdef MBEDTLS_ECP_DP_BP384R1_ENABLED
        case MBEDTLS_ECP_DP_BP384R1:
            return (const struct crypto_bignum *)CRYPTO_EC_A(e);
#endif
#ifdef MBEDTLS_ECP_DP_BP512R1_ENABLED
        case MBEDTLS_ECP_DP_BP512R1:
            return (const struct crypto_bignum *)CRYPTO_EC_A(e);
#endif
#ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
        case MBEDTLS_ECP_DP_CURVE25519:
            return (const struct crypto_bignum *)CRYPTO_EC_A(e);
#endif
#ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
        case MBEDTLS_ECP_DP_CURVE448:
            return (const struct crypto_bignum *)CRYPTO_EC_A(e);
#endif
        default:
            return NULL;
    }

    /*(note: not thread-safe; returns file-scoped static storage)*/
    if (mbedtls_mpi_read_binary(&mpi_sw_A, bin, len) == 0)
        return (const struct crypto_bignum *)&mpi_sw_A;
    return NULL;
}

const struct crypto_bignum *crypto_ec_get_b(struct crypto_ec *e)
{
    return (const struct crypto_bignum *)CRYPTO_EC_B(e);
}

const struct crypto_ec_point *crypto_ec_get_generator(struct crypto_ec *e)
{
    return (const struct crypto_ec_point *)CRYPTO_EC_G(e);
}

struct crypto_ec_point *crypto_ec_point_init(struct crypto_ec *e)
{
    if (TEST_FAIL())
        return NULL;

    mbedtls_ecp_point *p = os_malloc(sizeof(*p));
    if (p != NULL)
        mbedtls_ecp_point_init(p);
    return (struct crypto_ec_point *)p;
}

void crypto_ec_point_deinit(struct crypto_ec_point *p, int clear)
{
    mbedtls_ecp_point_free((mbedtls_ecp_point *)p);
    os_free(p);
}

int crypto_ec_point_x(struct crypto_ec *e, const struct crypto_ec_point *p, struct crypto_bignum *x)
{
    mbedtls_mpi *px = &((mbedtls_ecp_point *)p)->MBEDTLS_PRIVATE(X);
    return mbedtls_mpi_copy((mbedtls_mpi *)x, px) ? -1 : 0;
}

int crypto_ec_point_to_bin(struct crypto_ec *e, const struct crypto_ec_point *point, u8 *x, u8 *y)
{
    if (TEST_FAIL())
        return -1;

    /* crypto.h documents crypto_ec_point_to_bin() output is big-endian */
    size_t len = CRYPTO_EC_plen(e);
    if (x)
    {
        mbedtls_mpi *px = &((mbedtls_ecp_point *)point)->MBEDTLS_PRIVATE(X);
        if (mbedtls_mpi_write_binary(px, x, len))
            return -1;
    }
    if (y)
    {
        mbedtls_mpi *py = &((mbedtls_ecp_point *)point)->MBEDTLS_PRIVATE(Y);
        if (mbedtls_mpi_write_binary(py, y, len))
            return -1;
    }
    return 0;
}

struct crypto_ec_point *crypto_ec_point_from_bin(struct crypto_ec *e, const u8 *val)
{
    if (TEST_FAIL())
        return NULL;

    size_t len           = CRYPTO_EC_plen(e);
    mbedtls_ecp_point *p = os_malloc(sizeof(*p));
    u8 buf[1 + MBEDTLS_MPI_MAX_SIZE * 2];
    if (p == NULL)
        return NULL;
    mbedtls_ecp_point_init(p);

#ifdef MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED
    if (mbedtls_ecp_get_type((mbedtls_ecp_group *)e) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS)
    {
        buf[0] = 0x04;
        os_memcpy(buf + 1, val, len * 2);
        if (mbedtls_ecp_point_read_binary((mbedtls_ecp_group *)e, p, buf, 1 + len * 2) == 0)
            return (struct crypto_ec_point *)p;
    }
#endif
#ifdef MBEDTLS_ECP_MONTGOMERY_ENABLED
    if (mbedtls_ecp_get_type((mbedtls_ecp_group *)e) == MBEDTLS_ECP_TYPE_MONTGOMERY)
    {
        /* crypto.h interface documents crypto_ec_point_from_bin()
         * val is length: prime_len * 2 and is big-endian
         * (Short Weierstrass is assumed by hostap)
         * Reverse to little-endian format for Montgomery */
        for (unsigned int i = 0; i < len; ++i)
            buf[i] = val[len - 1 - i];
        if (mbedtls_ecp_point_read_binary((mbedtls_ecp_group *)e, p, buf, len) == 0)
            return (struct crypto_ec_point *)p;
    }
#endif

    mbedtls_ecp_point_free(p);
    os_free(p);
    return NULL;
}

int crypto_ec_point_add(struct crypto_ec *e,
                        const struct crypto_ec_point *a,
                        const struct crypto_ec_point *b,
                        struct crypto_ec_point *c)
{
    if (TEST_FAIL())
        return -1;

    /* mbedtls does not provide an mbedtls_ecp_point add function */
    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    int ret = mbedtls_mpi_lset(&one, 1) ||
                      mbedtls_ecp_muladd((mbedtls_ecp_group *)e, (mbedtls_ecp_point *)c, &one,
                                         (const mbedtls_ecp_point *)a, &one, (const mbedtls_ecp_point *)b) ?
                  -1 :
                  0;
    mbedtls_mpi_free(&one);
    return ret;
}

int crypto_ec_point_mul(struct crypto_ec *e,
                        const struct crypto_ec_point *p,
                        const struct crypto_bignum *b,
                        struct crypto_ec_point *res)
{
    if (TEST_FAIL())
        return -1;

    return mbedtls_ecp_mul((mbedtls_ecp_group *)e, (mbedtls_ecp_point *)res, (const mbedtls_mpi *)b,
                           (const mbedtls_ecp_point *)p, hostap_rng_fn, hostap_rng_ctx()) ?
               -1 :
               0;
}

int crypto_ec_point_invert(struct crypto_ec *e, struct crypto_ec_point *p)
{
    if (TEST_FAIL())
        return -1;

    if (mbedtls_ecp_get_type((mbedtls_ecp_group *)e) == MBEDTLS_ECP_TYPE_MONTGOMERY)
    {
        /* e.g. MBEDTLS_ECP_DP_CURVE25519 and MBEDTLS_ECP_DP_CURVE448 */
        wpa_printf(MSG_ERROR, "%s not implemented for Montgomery curves", __func__);
        return -1;
    }

    /* mbedtls does not provide an mbedtls_ecp_point invert function */
    /* below works for Short Weierstrass; incorrect for Montgomery curves */
    mbedtls_mpi *py = &((mbedtls_ecp_point *)p)->MBEDTLS_PRIVATE(Y);
    return mbedtls_ecp_is_zero((mbedtls_ecp_point *)p) /*point at infinity*/
                   || mbedtls_mpi_cmp_int(py, 0) == 0  /*point is its own inverse*/
                   || mbedtls_mpi_sub_abs(py, CRYPTO_EC_P(e), py) == 0 ?
               0 :
               -1;
}

#ifdef MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED
static int crypto_ec_point_y_sqr_weierstrass(mbedtls_ecp_group *e, const mbedtls_mpi *x, mbedtls_mpi *y2)
{
    /* MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS  y^2 = x^3 + a x + b    */

    /* Short Weierstrass elliptic curve group w/o A set treated as A = -3 */
    /* Attempt to match mbedtls/library/ecp.c:ecp_check_pubkey_sw() behavior
     * and elsewhere in mbedtls/library/ecp.c where if A is not set, it is
     * treated as if A = -3. */

    /* y^2 = x^3 + ax + b = (x^2 + a)x + b */
    return /* x^2 */
        mbedtls_mpi_mul_mpi(y2, x, x) ||
        mbedtls_mpi_mod_mpi(y2, y2, &e->P)
        /* x^2 + a */
        || (e->A.MBEDTLS_PRIVATE(p) ? mbedtls_mpi_add_mpi(y2, y2, &e->A) : mbedtls_mpi_sub_int(y2, y2, 3)) ||
        mbedtls_mpi_mod_mpi(y2, y2, &e->P)
        /* (x^2 + a)x */
        || mbedtls_mpi_mul_mpi(y2, y2, x) ||
        mbedtls_mpi_mod_mpi(y2, y2, &e->P)
        /* (x^2 + a)x + b */
        || mbedtls_mpi_add_mpi(y2, y2, &e->B) || mbedtls_mpi_mod_mpi(y2, y2, &e->P);
}
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

struct crypto_bignum *crypto_ec_point_compute_y_sqr(struct crypto_ec *e, const struct crypto_bignum *x)
{
    if (TEST_FAIL())
        return NULL;

    mbedtls_mpi *y2 = os_malloc(sizeof(*y2));
    if (y2 == NULL)
        return NULL;
    mbedtls_mpi_init(y2);

#ifdef MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED
    if (mbedtls_ecp_get_type((mbedtls_ecp_group *)e) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS &&
        crypto_ec_point_y_sqr_weierstrass((mbedtls_ecp_group *)e, (const mbedtls_mpi *)x, y2) == 0)
        return (struct crypto_bignum *)y2;
#endif

    mbedtls_mpi_free(y2);
    os_free(y2);
    return NULL;
}

int crypto_ec_point_is_at_infinity(struct crypto_ec *e, const struct crypto_ec_point *p)
{
    return mbedtls_ecp_is_zero((mbedtls_ecp_point *)p);
}

int crypto_ec_point_is_on_curve(struct crypto_ec *e, const struct crypto_ec_point *p)
{
    return mbedtls_ecp_check_pubkey((const mbedtls_ecp_group *)e, (const mbedtls_ecp_point *)p) == 0;
}

int crypto_ec_point_cmp(const struct crypto_ec *e, const struct crypto_ec_point *a, const struct crypto_ec_point *b)
{
    return mbedtls_ecp_point_cmp((const mbedtls_ecp_point *)a, (const mbedtls_ecp_point *)b);
}

#if !defined(CONFIG_NO_STDOUT_DEBUG)
void crypto_ec_point_debug_print(const struct crypto_ec *e, const struct crypto_ec_point *p, const char *title)
{
    u8 x[MBEDTLS_MPI_MAX_SIZE];
    u8 y[MBEDTLS_MPI_MAX_SIZE];
    size_t len = CRYPTO_EC_plen(e);
    /* crypto_ec_point_to_bin ought to take (const struct crypto_ec *e) */
    struct crypto_ec *ee;
    *(const struct crypto_ec **)&ee = e; /*(cast away const)*/
    if (crypto_ec_point_to_bin(ee, p, x, y) == 0)
    {
        if (title)
            wpa_printf(MSG_DEBUG, "%s", title);
        wpa_hexdump(MSG_DEBUG, "x:", x, len);
        wpa_hexdump(MSG_DEBUG, "y:", y, len);
    }
}
#else
void crypto_ec_point_debug_print(const struct crypto_ec *e, const struct crypto_ec_point *p, const char *title)
{
	// Fixing linking error undefined reference to `crypto_ec_point_debug_print'
}
#endif

#include <psa/crypto.h>
#include <mbedtls/oid.h>

struct crypto_ec_key *crypto_ec_key_parse_priv(const u8 *der, size_t der_len)
{
    mbedtls_pk_context *pk;

    pk = os_calloc(sizeof(mbedtls_pk_context), 1);
    if (pk == NULL)
        return NULL;

    mbedtls_pk_init(pk);
    if (mbedtls_pk_parse_key(pk, der, der_len, NULL, 0) != 0) {
        mbedtls_pk_free(pk);
        os_free(pk);
        return NULL;
    }

    return (struct crypto_ec_key *) pk;
}

struct crypto_ec_key * crypto_ec_key_set_priv(int group, const u8 *raw, size_t raw_len)
{
    mbedtls_pk_context *pk;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_ecc_family_t ec_family;
    psa_key_bits_t key_bits;
    mbedtls_ecp_group_id ecp_group_id;
    int ret;

    ecp_group_id = crypto_mbedtls_ecp_group_id_from_ike_id(group);
    ec_family = mbedtls_ecc_group_to_psa(ecp_group_id, (size_t *) &key_bits);
    if (ec_family == 0) {
        return NULL;
    }

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(ec_family));
    psa_set_key_bits(&key_attr, key_bits);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    if (psa_import_key(&key_attr, raw, raw_len, &key_id) != PSA_SUCCESS) {
        return NULL;
    }

    pk = os_calloc(sizeof(mbedtls_pk_context), 1);
    if (pk == NULL) {
        psa_destroy_key(key_id);
        return NULL;
    }

    mbedtls_pk_init(pk);
    ret = mbedtls_pk_copy_from_psa(key_id, pk);
    psa_destroy_key(key_id);
    if (ret != 0) {
        mbedtls_pk_free(pk);
        os_free(pk);
        return NULL;
    }

    return (struct crypto_ec_key *) pk;
}

struct crypto_ec_key *crypto_ec_key_parse_pub(const u8 *der, size_t der_len)
{
    mbedtls_pk_context *pk;

    pk = os_calloc(sizeof(mbedtls_pk_context), 1);
    if (pk == NULL)
        return NULL;

    mbedtls_pk_init(pk);
    if (mbedtls_pk_parse_public_key(pk, der, der_len) != 0) {
        mbedtls_pk_free(pk);
        os_free(pk);
        return NULL;
    }

    return (struct crypto_ec_key *) pk;
}

#ifdef CRYPTO_MBEDTLS_CRYPTO_EC_DPP

struct crypto_ec_key *crypto_ec_key_set_pub(int group, const u8 *x, const u8 *y, size_t len)
{
    mbedtls_pk_context *pk;
    mbedtls_ecp_group_id group_id = crypto_mbedtls_ecp_group_id_from_ike_id(group);
    uint8_t *raw_key_ptr;
    psa_ecc_family_t ec_family;
    psa_key_bits_t key_bits;

    ec_family = mbedtls_ecc_group_to_psa(group_id, (size_t *) &key_bits);
    if (ec_family == 0) {
        return NULL;
    }

    /* Ensure data will fit into pk->pub_raw */
    if ((2 * len + 1) > MBEDTLS_PK_MAX_PUBKEY_RAW_LEN) {
        return NULL;
    }

    pk = os_calloc(sizeof(mbedtls_pk_context), 1);
    if (pk == NULL) {
        return NULL;
    }

    raw_key_ptr = pk->MBEDTLS_PRIVATE(pub_raw);
    *raw_key_ptr = 0x04;
    raw_key_ptr++;
    memcpy(raw_key_ptr, x, len);
    raw_key_ptr += len;
    memcpy(raw_key_ptr, y, len);

    pk->MBEDTLS_PRIVATE(ec_family) = ec_family;
    pk->MBEDTLS_PRIVATE(bits) = key_bits;

    return (struct crypto_ec_key *) pk;
}

struct crypto_ec_key *crypto_ec_key_set_pub_point(struct crypto_ec *e, const struct crypto_ec_point *pub)
{
    mbedtls_ecp_group *ecp_group = (mbedtls_ecp_group *) e;
    mbedtls_ecp_point *ecp_point = (mbedtls_ecp_point *) pub;
    uint8_t key[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)] = { 0 };
    uint8_t *x, *y;
    size_t key_len, coord_len;
    int crypto_group;

    if (mbedtls_ecp_point_write_binary(ecp_group, ecp_point, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &key_len, key, sizeof(key)) != 0) {
        return NULL;
    }

    coord_len = (key_len - 1) / 2;
    crypto_group = crypto_mbedtls_ike_id_from_ecp_group_id(ecp_group->id);
    x = &key[1];
    y = x + coord_len;

    return crypto_ec_key_set_pub(crypto_group, x, y, coord_len);
}

struct crypto_ec_key *crypto_ec_key_gen(int group)
{
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    mbedtls_pk_context *pk;
    int ret;

    if (crypto_mbedtls_keypair_gen(group, &key_id) != 0) {
        return NULL;
    }

    pk = os_malloc(sizeof(mbedtls_pk_context));
    if (pk == NULL) {
        psa_destroy_key(key_id);
    }

    mbedtls_pk_init(pk);
    ret = mbedtls_pk_copy_from_psa(key_id, pk);
    psa_destroy_key(key_id);
    if (ret != 0) {
        mbedtls_pk_free(pk);
        os_free(pk);
        return NULL;
    }

    return (struct crypto_ec_key *) pk;
}

#endif /* CRYPTO_MBEDTLS_CRYPTO_EC_DPP */

void crypto_ec_key_deinit(struct crypto_ec_key *key)
{
    mbedtls_pk_context *pk = (mbedtls_pk_context *) key;

    mbedtls_pk_free(pk);
    os_free(key);
}

/* Internal - from pkwrite.h */
#define MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES    \
    (29 + PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS))

struct wpabuf *crypto_ec_key_get_subject_public_key(struct crypto_ec_key *key)
{
    mbedtls_pk_context *pk = (mbedtls_pk_context *) key;
    struct wpabuf *buf, *buf2;
    uint8_t *p;
    int ret;

    buf = wpabuf_alloc(MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES);
    if (buf == NULL) {
        return NULL;
    }

    /* The buffer is written starting from the end! "ret" is the amount of data written. */
    ret = mbedtls_pk_write_pubkey_der(pk, wpabuf_mhead(buf), wpabuf_len(buf));
    if (ret < 0) {
        wpabuf_free(buf);
        return NULL;
    }

    p = wpabuf_mhead_u8(buf) + wpabuf_len(buf) - ret;

    /* TODO: convert data to use compressed point format */

    buf2 = wpabuf_alloc_copy(p, ret);
    wpabuf_free(buf);

    return buf2;
}

#ifdef CRYPTO_MBEDTLS_CRYPTO_EC_DPP

/* Internal - from pkwrite.h */
#define MBEDTLS_PK_ECP_PRV_DER_MAX_BYTES    \
    (8 + PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS) + \
     16 + 4 + PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS))

struct wpabuf *crypto_ec_key_get_ecprivate_key(struct crypto_ec_key *key, bool include_pub)
{
    mbedtls_pk_context *pk = (mbedtls_pk_context *) key;
    struct wpabuf *buf, *buf2;
    uint8_t *p;
    int ret;

    buf = wpabuf_alloc(MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES);
    if (buf == NULL) {
        return NULL;
    }

    /* The buffer is written starting from the end! "ret" is the amount of data written. */
    ret = mbedtls_pk_write_key_der(pk, wpabuf_mhead(buf), wpabuf_len(buf));
    if (ret < 0) {
        wpabuf_free(buf);
        return NULL;
    }

    p = wpabuf_mhead_u8(buf) + wpabuf_len(buf) - ret;

    buf2 = wpabuf_alloc_copy(p, ret);
    wpabuf_free(buf);

    return buf2;
}

struct wpabuf *crypto_ec_key_get_pubkey_point(struct crypto_ec_key *key, int prefix)
{
    mbedtls_pk_context *pk = (mbedtls_pk_context *) key;
    uint8_t *key_ptr = pk->MBEDTLS_PRIVATE(pub_raw);
    size_t key_len = pk->MBEDTLS_PRIVATE(pub_raw_len);
    struct wpabuf *buf;

    if (prefix) {
        buf = wpabuf_alloc_copy(key_ptr, key_len);
    } else {
        buf = wpabuf_alloc_copy(key_ptr + 1, key_len - 1);
    }
    if (buf == NULL) {
        return NULL;
    }

    return buf;
}

struct crypto_ec_point *crypto_ec_key_get_public_key(struct crypto_ec_key *key)
{
    mbedtls_pk_context *pk = (mbedtls_pk_context *) key;
    uint8_t *key_ptr = pk->MBEDTLS_PRIVATE(pub_raw);
    size_t key_len = pk->MBEDTLS_PRIVATE(pub_raw_len);
    mbedtls_ecp_point *ecp_point;
    mbedtls_ecp_group ecp_group;
    mbedtls_ecp_group_id ecp_group_id;
    int ret;

    ecp_group_id = mbedtls_ecc_group_from_psa(pk->MBEDTLS_PRIVATE(ec_family),
                                              pk->MBEDTLS_PRIVATE(bits));
    if (ecp_group_id == 0) {
        return NULL;
    }

    ecp_point = os_malloc(sizeof(mbedtls_ecp_point));
    if (ecp_point == NULL) {
        return NULL;
    }

    mbedtls_ecp_point_init(ecp_point);
    mbedtls_ecp_group_init(&ecp_group);
    if (mbedtls_ecp_group_load(&ecp_group, ecp_group_id) != 0) {
        os_free(ecp_point);
        return NULL;
    }
    ret = mbedtls_ecp_point_read_binary(&ecp_group, ecp_point, key_ptr, key_len);
    mbedtls_ecp_group_free(&ecp_group);
    if (ret != 0) {
        os_free(ecp_point);
        return NULL;
    }

    return (struct crypto_ec_point *) ecp_point;
}

struct crypto_bignum *crypto_ec_key_get_private_key(struct crypto_ec_key *key)
{
    mbedtls_pk_context *pk = (mbedtls_pk_context *) key;
    uint8_t priv_key[PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)] = { 0 };
    size_t priv_key_len;
    mbedtls_mpi *mpi;

    mpi = os_malloc(sizeof(mbedtls_mpi));
    if (mpi == NULL) {
        return NULL;
    }

    mbedtls_mpi_init(mpi);
    if (psa_export_key(pk->MBEDTLS_PRIVATE(priv_id), priv_key, sizeof(priv_key), &priv_key_len) != PSA_SUCCESS) {
        os_free(mpi);
        return NULL;
    }

    if (mbedtls_mpi_read_binary(mpi, priv_key, priv_key_len) != 0) {
        memset(priv_key, 0, sizeof(priv_key));
        os_free(mpi);
        return NULL;
    }

    return (struct crypto_bignum *) mpi;
}

#endif /* CRYPTO_MBEDTLS_CRYPTO_EC_DPP */

static mbedtls_md_type_t crypto_ec_key_sign_md(size_t len)
{
    /* get mbedtls_md_type_t from length of hash data to be signed */
    switch (len)
    {
        case 64:
            return MBEDTLS_MD_SHA512;
        case 48:
            return MBEDTLS_MD_SHA384;
        case 32:
            return MBEDTLS_MD_SHA256;
        case 20:
            return MBEDTLS_MD_SHA1;
        case 16:
            return MBEDTLS_MD_MD5;
        default:
            return MBEDTLS_MD_NONE;
    }
}

struct wpabuf *crypto_ec_key_sign(struct crypto_ec_key *key, const u8 *data, size_t len)
{
    mbedtls_pk_context *pk = (mbedtls_pk_context *) key;
    mbedtls_md_type_t md_alg = crypto_ec_key_sign_md(len);
    uint8_t sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    struct wpabuf *buf;
    size_t sig_len;

    if (mbedtls_pk_sign(pk, md_alg, data, len, sig, sizeof(sig), &sig_len) != 0) {
        return NULL;
    }

    buf = wpabuf_alloc_copy(sig, sig_len);
    if (buf == NULL) {
        return NULL;
    }

    return buf;
}

#ifdef CRYPTO_MBEDTLS_CRYPTO_EC_DPP
struct wpabuf *crypto_ec_key_sign_r_s(struct crypto_ec_key *key, const u8 *data, size_t len)
{
    mbedtls_pk_context *pk = (mbedtls_pk_context *) key;
    mbedtls_md_type_t md_alg = crypto_ec_key_sign_md(len);
    uint8_t sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    uint8_t sig_raw[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t sig_len, sig_raw_len;
    size_t bits;
    struct wpabuf *buf;

    if (mbedtls_pk_sign(pk, md_alg, data, len, sig, sizeof(sig), &sig_len) != 0) {
        return NULL;
    }

    bits = mbedtls_pk_get_bitlen(pk);
    if (mbedtls_ecdsa_der_to_raw(bits, sig, sig_len, sig_raw, sizeof(sig_raw), &sig_raw_len) != 0) {
        return NULL;
    }

    buf = wpabuf_alloc_copy(sig_raw, sig_raw_len);
    if (buf == NULL) {
        return NULL;
    }

    return buf;
}
#endif /* CRYPTO_MBEDTLS_CRYPTO_EC_DPP */

int crypto_ec_key_verify_signature(struct crypto_ec_key *key, const u8 *data, size_t len,
                                   const u8 *sig, size_t sig_len)
{
    mbedtls_pk_context *pk = (mbedtls_pk_context *) key;
    mbedtls_md_type_t md_alg = crypto_ec_key_sign_md(len);
    int ret;

    ret = mbedtls_pk_verify(pk, md_alg, data, len, sig, sig_len);
    switch (ret) {
        case 0:
            return 1;
        case PSA_ERROR_INVALID_SIGNATURE:
            return 0;
        default:
            return -1;
    }
}

#ifdef CRYPTO_MBEDTLS_CRYPTO_EC_DPP
int crypto_ec_key_verify_signature_r_s(struct crypto_ec_key *key, const u8 *data, size_t len,
                                       const u8 *r, size_t r_len, const u8 *s, size_t s_len)
{
    mbedtls_pk_context *pk = (mbedtls_pk_context *) key;
    uint8_t sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE] = { 0 };
    uint8_t sig_raw[MBEDTLS_PK_SIGNATURE_MAX_SIZE] = { 0 };
    size_t bits, sig_raw_len, sig_len;

    memcpy(sig_raw, r, r_len);
    memcpy(sig_raw + r_len, s, s_len);
    sig_raw_len = r_len + s_len;

    bits = mbedtls_pk_get_bitlen(pk);
    if (mbedtls_ecdsa_raw_to_der(bits, sig_raw, sig_raw_len, sig, sizeof(sig), &sig_len) != 0) {
        return -1;
    }

    return crypto_ec_key_verify_signature(key, data, len, sig, sig_len);
}
#endif /* CRYPTO_MBEDTLS_CRYPTO_EC_DPP */

int crypto_ec_key_group(struct crypto_ec_key *key)
{
    mbedtls_pk_context *pk = (mbedtls_pk_context *) key;
    mbedtls_ecp_group_id ecp_group_id;

    ecp_group_id = mbedtls_ecc_group_from_psa(pk->MBEDTLS_PRIVATE(ec_family),
                                              pk->MBEDTLS_PRIVATE(bits));
    return crypto_mbedtls_ike_id_from_ecp_group_id(ecp_group_id);
}

#ifdef CRYPTO_MBEDTLS_CRYPTO_EC_DPP

int crypto_ec_key_cmp(struct crypto_ec_key *key1, struct crypto_ec_key *key2)
{
    mbedtls_pk_context *pk1 = (mbedtls_pk_context *) key1;
    mbedtls_pk_context *pk2 = (mbedtls_pk_context *) key2;
    uint8_t priv_key1[PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)] = { 0 };
    uint8_t priv_key2[PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)] = { 0 };
    size_t priv_key1_len, priv_key2_len;

    if ((psa_export_key(pk1->MBEDTLS_PRIVATE(priv_id), priv_key1, sizeof(priv_key1), &priv_key1_len) != PSA_SUCCESS) ||
        (psa_export_key(pk2->MBEDTLS_PRIVATE(priv_id), priv_key2, sizeof(priv_key2), &priv_key2_len) != PSA_SUCCESS)) {
        memset(priv_key1, 0, sizeof(priv_key1));
        memset(priv_key2, 0, sizeof(priv_key2));
        return -1;
    }

    if ((priv_key1_len != priv_key2_len) ||
        (pk1->MBEDTLS_PRIVATE(pub_raw_len) != pk2->MBEDTLS_PRIVATE(pub_raw_len)) ||
        (memcmp(priv_key1, priv_key2, priv_key1_len) != 0) ||
        (memcmp(pk1->MBEDTLS_PRIVATE(pub_raw), pk2->MBEDTLS_PRIVATE(pub_raw), pk1->MBEDTLS_PRIVATE(pub_raw_len)) != 0)) {
        memset(priv_key1, 0, sizeof(priv_key1));
        memset(priv_key2, 0, sizeof(priv_key2));
        return -1;
    }

    return 0;
}

void crypto_ec_key_debug_print(const struct crypto_ec_key *key, const char *title)
{
    /* TBD: what info is desirable here and in what human readable format?*/
    /*(crypto_openssl.c prints a human-readably public key and attributes)*/
    wpa_printf(MSG_DEBUG, "%s: %s not implemented", title, __func__);
}

#endif /* CRYPTO_MBEDTLS_CRYPTO_EC_DPP */

#endif /* CRYPTO_MBEDTLS_CRYPTO_EC */

#ifdef CRYPTO_MBEDTLS_CRYPTO_CSR

#include <mbedtls/x509_csr.h>
#include <mbedtls/oid.h>

struct crypto_csr *crypto_csr_init(void)
{
    mbedtls_x509write_csr *csr = os_malloc(sizeof(*csr));
    if (csr != NULL)
        mbedtls_x509write_csr_init(csr);
    return (struct crypto_csr *)csr;
}

struct crypto_csr *crypto_csr_verify(const struct wpabuf *req)
{
    /* future: look for alternatives to MBEDTLS_PRIVATE() access */

    /* sole caller src/common/dpp_crypto.c:dpp_validate_csr()
     * uses (mbedtls_x509_csr *) to obtain CSR_ATTR_CHALLENGE_PASSWORD
     * so allocate different object (mbedtls_x509_csr *) and special-case
     * object when used in crypto_csr_get_attribute() and when free()d in
     * crypto_csr_deinit(). */

    mbedtls_x509_csr *csr = os_malloc(sizeof(*csr));
    if (csr == NULL)
        return NULL;
    mbedtls_x509_csr_init(csr);
    const mbedtls_md_info_t *md_info;
    unsigned char digest[MBEDTLS_MD_MAX_SIZE];
    if (mbedtls_x509_csr_parse_der(csr, wpabuf_head(req), wpabuf_len(req)) == 0 &&
        (md_info = mbedtls_md_info_from_type(csr->MBEDTLS_PRIVATE(sig_md))) != NULL &&
        mbedtls_md(md_info, csr->cri.p, csr->cri.len, digest) == 0)
    {
        switch (mbedtls_pk_verify(&csr->pk, csr->MBEDTLS_PRIVATE(sig_md), digest, mbedtls_md_get_size(md_info),
                                  csr->MBEDTLS_PRIVATE(sig).p, csr->MBEDTLS_PRIVATE(sig).len))
        {
            case 0:
                /*case MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH:*/ /* XXX: allow? */
                return (struct crypto_csr *)((uintptr_t)csr | 1uL);
            default:
                break;
        }
    }

    mbedtls_x509_csr_free(csr);
    os_free(csr);
    return NULL;
}

void crypto_csr_deinit(struct crypto_csr *csr)
{
    if ((uintptr_t)csr & 1uL) {
        csr = (struct crypto_csr *)((uintptr_t)csr & ~1uL);
    }

    mbedtls_x509_csr *csr_ctx = (mbedtls_x509_csr *) csr;
    mbedtls_x509_csr_free(csr_ctx);
    os_free(csr);
}

int crypto_csr_set_ec_public_key(struct crypto_csr *csr, struct crypto_ec_key *key)
{
    mbedtls_x509write_csr_set_key((mbedtls_x509write_csr *) csr, (mbedtls_pk_context *) key);

    return 0;
}

int crypto_csr_set_name(struct crypto_csr *csr, enum crypto_csr_name type, const char *name)
{
    /* specialized for src/common/dpp_crypto.c */

    /* sole caller src/common/dpp_crypto.c:dpp_build_csr()
     * calls this function only once, using type == CSR_NAME_CN
     * (If called more than once, this code would need to append
     *  components to the subject name, which we could do by
     *  appending to (mbedtls_x509write_csr *) private member
     *  mbedtls_asn1_named_data *MBEDTLS_PRIVATE(subject)) */

    const char *label;
    switch (type)
    {
        case CSR_NAME_CN:
            label = "CN=";
            break;
        case CSR_NAME_SN:
            label = "SN=";
            break;
        case CSR_NAME_C:
            label = "C=";
            break;
        case CSR_NAME_O:
            label = "O=";
            break;
        case CSR_NAME_OU:
            label = "OU=";
            break;
        default:
            return -1;
    }

    size_t len         = strlen(name);
    struct wpabuf *buf = wpabuf_alloc(3 + len + 1);
    if (buf == NULL)
        return -1;
    wpabuf_put_data(buf, label, strlen(label));
    wpabuf_put_data(buf, name, len + 1); /*(include trailing '\0')*/
    /* Note: 'name' provided is set as given and should be backslash-escaped
     * by caller when necessary, e.g. literal ',' which are not separating
     * components should be backslash-escaped */

    int ret = mbedtls_x509write_csr_set_subject_name((mbedtls_x509write_csr *)csr, wpabuf_head(buf)) ? -1 : 0;
    wpabuf_free(buf);
    return ret;
}

/* OBJ_pkcs9_challengePassword  1 2 840 113549 1 9 7 */
static const char OBJ_pkcs9_challengePassword[] = MBEDTLS_OID_PKCS9 "\x07";

int crypto_csr_set_attribute(
    struct crypto_csr *csr, enum crypto_csr_attr attr, int attr_type, const u8 *value, size_t len)
{
    /* specialized for src/common/dpp_crypto.c */
    /* sole caller src/common/dpp_crypto.c:dpp_build_csr() passes
     *   attr      == CSR_ATTR_CHALLENGE_PASSWORD
     *   attr_type == ASN1_TAG_UTF8STRING */

    const char *oid;
    size_t oid_len;
    switch (attr)
    {
        case CSR_ATTR_CHALLENGE_PASSWORD:
            oid     = OBJ_pkcs9_challengePassword;
            oid_len = sizeof(OBJ_pkcs9_challengePassword) - 1;
            break;
        default:
            return -1;
    }

    (void)oid;
    (void)oid_len;

    /* mbedtls does not currently provide way to set an attribute in a CSR:
     *   https://github.com/Mbed-TLS/mbedtls/issues/4886 */
    wpa_printf(MSG_ERROR,
               "mbedtls does not currently support setting challengePassword "
               "attribute in CSR");
    return -1;
}

const u8 *mbedtls_x509_csr_attr_oid_value(
    mbedtls_x509_csr *csr, const char *oid, size_t oid_len, size_t *vlen, int *vtype)
{
    /* Note: mbedtls_x509_csr_parse_der() has parsed and validated CSR,
     *	   so validation checks are not repeated here
     *
     * It would be nicer if (mbedtls_x509_csr *) had an mbedtls_x509_buf of
     * Attributes (or at least a pointer) since mbedtls_x509_csr_parse_der()
     * already parsed the rest of CertificationRequestInfo, some of which is
     * repeated here to step to Attributes.  Since csr->subject_raw.p points
     * into csr->cri.p, which points into csr->raw.p, step over version and
     * subject of CertificationRequestInfo (SEQUENCE) */
    unsigned char *p   = csr->subject_raw.p + csr->subject_raw.len;
    unsigned char *end = csr->cri.p + csr->cri.len, *ext;
    size_t len;

    /* step over SubjectPublicKeyInfo */
    mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    p += len;

    /* Attributes
     *   { ATTRIBUTE:IOSet } ::= SET OF { SEQUENCE { OID, value } }
     */
    if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) != 0)
    {
        return NULL;
    }
    while (p < end)
    {
        if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        {
            return NULL;
        }
        ext = p;
        p += len;

        if (mbedtls_asn1_get_tag(&ext, end, &len, MBEDTLS_ASN1_OID) != 0)
            return NULL;
        if (oid_len != len || 0 != memcmp(ext, oid, oid_len))
            continue;

        /* found oid; return value */
        *vtype = *ext++; /* tag */
        return (mbedtls_asn1_get_len(&ext, end, vlen) == 0) ? ext : NULL;
    }

    return NULL;
}

const u8 *crypto_csr_get_attribute(struct crypto_csr *csr, enum crypto_csr_attr attr, size_t *len, int *type)
{
    /* specialized for src/common/dpp_crypto.c */
    /* sole caller src/common/dpp_crypto.c:dpp_build_csr() passes
     *   attr == CSR_ATTR_CHALLENGE_PASSWORD */

    const char *oid;
    size_t oid_len;
    switch (attr)
    {
        case CSR_ATTR_CHALLENGE_PASSWORD:
            oid     = OBJ_pkcs9_challengePassword;
            oid_len = sizeof(OBJ_pkcs9_challengePassword) - 1;
            break;
        default:
            return NULL;
    }

    /* see crypto_csr_verify(); expecting (mbedtls_x509_csr *) tagged |=1 */
    if (!((uintptr_t)csr & 1uL))
        return NULL;
    csr = (struct crypto_csr *)((uintptr_t)csr & ~1uL);

    return mbedtls_x509_csr_attr_oid_value((mbedtls_x509_csr *)csr, oid, oid_len, len, type);
}

struct wpabuf *crypto_csr_sign(struct crypto_csr *csr, struct crypto_ec_key *key, enum crypto_hash_alg algo)
{
    mbedtls_md_type_t sig_md;
    switch (algo)
    {
        case CRYPTO_HASH_ALG_SHA256:
            sig_md = MBEDTLS_MD_SHA256;
            break;
        case CRYPTO_HASH_ALG_SHA384:
            sig_md = MBEDTLS_MD_SHA384;
            break;
        case CRYPTO_HASH_ALG_SHA512:
            sig_md = MBEDTLS_MD_SHA512;
            break;
        default:
            return NULL;
    }
    mbedtls_x509write_csr_set_md_alg((mbedtls_x509write_csr *)csr, sig_md);

    unsigned char buf[4096]; /* XXX: large enough?  too large? */
    int len = mbedtls_x509write_csr_der((mbedtls_x509write_csr *)csr, buf, sizeof(buf));
    if (len < 0)
        return NULL;
    /*  Note: data is written at the end of the buffer! Use the
     *        return value to determine where you should start
     *        using the buffer */
    return wpabuf_alloc_copy(buf + sizeof(buf) - len, (size_t)len);
}

#endif /* CRYPTO_MBEDTLS_CRYPTO_CSR */

#ifdef CRYPTO_MBEDTLS_CRYPTO_PKCS7
struct wpabuf *crypto_pkcs7_get_certificates(const struct wpabuf *pkcs7)
{
    return NULL;
}
#endif /* CRYPTO_MBEDTLS_CRYPTO_PKCS7 */

#ifdef CRYPTO_MBEDTLS_CRYPTO_HPKE

struct wpabuf *hpke_base_seal(enum hpke_kem_id kem_id,
                              enum hpke_kdf_id kdf_id,
                              enum hpke_aead_id aead_id,
                              struct crypto_ec_key *peer_pub,
                              const u8 *info,
                              size_t info_len,
                              const u8 *aad,
                              size_t aad_len,
                              const u8 *pt,
                              size_t pt_len)
{
    /* not yet implemented */
    return NULL;
}

struct wpabuf *hpke_base_open(enum hpke_kem_id kem_id,
                              enum hpke_kdf_id kdf_id,
                              enum hpke_aead_id aead_id,
                              struct crypto_ec_key *own_priv,
                              const u8 *info,
                              size_t info_len,
                              const u8 *aad,
                              size_t aad_len,
                              const u8 *enc_ct,
                              size_t enc_ct_len)
{
    /* not yet implemented */
    return NULL;
}
#endif

#endif
