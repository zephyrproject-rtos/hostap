/** @file supp_psa_api.h
 *
 *  @brief  This file provides crypto mbedtls PSA APIs for wpa supplicant.
 *
 *  Copyright 2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef SUPP_PSA_API_H
#define SUPP_PSA_API_H

#include "includes.h"
#include "common.h"

#include "psa/crypto.h"
#include "mbedtls/md.h"

typedef enum
{
    SUPP_PSA_BLOCK_SIZE_128 = 16,
    SUPP_PSA_BLOCK_SIZE_160 = 20,
    SUPP_PSA_BLOCK_SIZE_192 = 24,
    SUPP_PSA_BLOCK_SIZE_244 = 28,
    SUPP_PSA_BLOCK_SIZE_256 = 32,
    SUPP_PSA_BLOCK_SIZE_384 = 48,
    SUPP_PSA_BLOCK_SIZE_512 = 64,
} supp_psa_block_size_e;

typedef enum
{
    SUPP_PSA_KEY_BITS_128 = 128,
    SUPP_PSA_KEY_BITS_192 = 192,
    SUPP_PSA_KEY_BITS_256 = 256,
} supp_psa_key_bits_e;

int aes_128_encrypt_block_psa(const u8 *key, const u8 *in, u8 *out);
int aes_128_cbc_encrypt_psa(const u8 *key, const u8 *iv, u8 *data, size_t data_len);
int aes_128_cbc_decrypt_psa(const u8 *key, const u8 *iv, u8 *data, size_t data_len);
int aes_ctr_encrypt_psa(const u8 *key, size_t key_len, const u8 *nonce, u8 *data, size_t data_len);

int omac1_aes_vector_psa(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac);

int md_vector_psa(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac, mbedtls_md_type_t md_type);

int hmac_vector_psa(const u8 *key,
                    size_t key_len,
                    size_t num_elem,
                    const u8 *addr[],
                    const size_t *len,
                    u8 *mac,
                    mbedtls_md_type_t md_type);

int pbkdf2_sha1_psa(mbedtls_md_type_t md_alg,
                    const u8 *password, size_t plen,
                    const unsigned char *salt, size_t slen,
                    unsigned int iteration_count, uint32_t key_length,
                    unsigned char *output);

int supp_psa_crypto_init(void);
void supp_psa_crypto_deinit(void);
#endif /* SUPP_PSA_API_H */
