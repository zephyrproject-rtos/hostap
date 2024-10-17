/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Copyright 2023-2024 NXP
 *
 *  @file  supp_psa_api.c
 *  @brief This file provides wpa supplicant crypto mbedtls PSA APIs.
 */

#include "supp_psa_api.h"
#ifdef CONFIG_WIFI_NM_WPA_SUPPLICANT_CRYPTO_TEST
#include "module_tests.h"
#endif

#define ASSERT_STATUS(actual, expected)                                            \
    do                                                                             \
    {                                                                              \
        if ((actual) != (expected))                                                \
        {                                                                          \
            printk(                                                                \
                "\tassertion failed at %s:%d - "                                   \
                "actual:%d expected:%d\r\n",                                       \
                __FILE__, __LINE__, (psa_status_t)actual, (psa_status_t)expected); \
            goto exit;                                                             \
        }                                                                          \
    } while (0)

#define SUPP_PSA_MAX_OUTPUT_SIZE 2048

static uint8_t supp_psa_outbuf[SUPP_PSA_MAX_OUTPUT_SIZE];

static inline void supp_psa_set_attributes(psa_key_attributes_t *attributes, u32 type, u32 alg, u32 usage)
{
    psa_set_key_type(attributes, type);
    psa_set_key_algorithm(attributes, alg);
    psa_set_key_usage_flags(attributes, usage);
}

static void supp_psa_get_hash_alg(mbedtls_md_type_t type, psa_algorithm_t *alg, int *block_size)
{
    switch (type)
    {
        case MBEDTLS_MD_MD5:
            *alg = PSA_ALG_MD5;
            break;
        case MBEDTLS_MD_SHA1:
            *alg = PSA_ALG_SHA_1;
            break;
        case MBEDTLS_MD_SHA224:
            *alg = PSA_ALG_SHA_224;
            break;
        case MBEDTLS_MD_SHA256:
            *alg = PSA_ALG_SHA_256;
            break;
        case MBEDTLS_MD_SHA384:
            *alg = PSA_ALG_SHA_384;
            break;
        case MBEDTLS_MD_SHA512:
            *alg = PSA_ALG_SHA_512;
            break;
        case MBEDTLS_MD_RIPEMD160:
            *alg = PSA_ALG_RIPEMD160;
            break;
        default:
            *alg = PSA_ALG_NONE;
            break;
    }
    *block_size = PSA_HASH_LENGTH(*alg);
}

static psa_status_t supp_psa_cipher_operation(psa_cipher_operation_t *operation,
                                              const uint8_t *input,
                                              size_t input_size,
                                              size_t part_size,
                                              uint8_t *output,
                                              size_t output_size,
                                              size_t *output_len)
{
    psa_status_t status;
    size_t bytes_to_write = 0;
    size_t bytes_written  = 0;
    size_t len            = 0;

    *output_len = 0;
    while (bytes_written != input_size)
    {
        bytes_to_write = (input_size - bytes_written > part_size ? part_size : input_size - bytes_written);

        status = psa_cipher_update(operation, input + bytes_written, bytes_to_write, output + *output_len,
                                   output_size - *output_len, &len);
        ASSERT_STATUS(status, PSA_SUCCESS);

        bytes_written += bytes_to_write;
        *output_len += len;
    }

    status = psa_cipher_finish(operation, output + *output_len, output_size - *output_len, &len);
    ASSERT_STATUS(status, PSA_SUCCESS);
    *output_len += len;

exit:
    return status;
}

#if defined(MBEDTLS_AES_C) || defined(CONFIG_PSA_WANT_KEY_TYPE_AES)
#define SUPP_PSA_AES_BLOCK_SIZE 16

int aes_128_encrypt_block_psa(const u8 *key, const u8 *in, u8 *out)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id     = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t alg             = PSA_ALG_ECB_NO_PADDING;
    size_t out_len                  = 0;

    supp_psa_set_attributes(&attributes, PSA_KEY_TYPE_AES, alg, PSA_KEY_USAGE_ENCRYPT);

    status = psa_import_key(&attributes, key, SUPP_PSA_BLOCK_SIZE_128, &key_id);
    ASSERT_STATUS(status, PSA_SUCCESS);
    psa_reset_key_attributes(&attributes);

    status = psa_cipher_encrypt(key_id, alg, in, SUPP_PSA_BLOCK_SIZE_128, out, SUPP_PSA_BLOCK_SIZE_128, &out_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    if (key_id != MBEDTLS_SVC_KEY_ID_INIT)
    {
        psa_destroy_key(key_id);
    }
    return (int)status;
}

int aes_128_cbc_encrypt_psa(const u8 *key, const u8 *iv, u8 *data, size_t data_len)
{
    psa_status_t status;
    psa_key_attributes_t attributes  = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id      = MBEDTLS_SVC_KEY_ID_INIT;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    psa_key_type_t key_type          = PSA_KEY_TYPE_AES;
    psa_algorithm_t alg              = PSA_ALG_CBC_NO_PADDING;
    size_t out_len                   = 0;

    if (data_len > SUPP_PSA_MAX_OUTPUT_SIZE)
    {
        printk("%s invalid input len %d", __func__, data_len);
        return -1;
    }

    supp_psa_set_attributes(&attributes, key_type, alg, PSA_KEY_USAGE_ENCRYPT);

    status = psa_import_key(&attributes, key, SUPP_PSA_BLOCK_SIZE_128, &key_id);
    ASSERT_STATUS(status, PSA_SUCCESS);
    psa_reset_key_attributes(&attributes);

    status = psa_cipher_encrypt_setup(&operation, key_id, alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_cipher_set_iv(&operation, iv, PSA_CIPHER_IV_LENGTH(key_type, alg));
    ASSERT_STATUS(status, PSA_SUCCESS);

    memset(supp_psa_outbuf, 0x0, data_len);
    status = supp_psa_cipher_operation(&operation, data, data_len, PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type),
                                       supp_psa_outbuf, data_len, &out_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    memcpy(data, supp_psa_outbuf, out_len);
exit:
    psa_cipher_abort(&operation);
    if (key_id != MBEDTLS_SVC_KEY_ID_INIT)
    {
        psa_destroy_key(key_id);
    }
    return (int)status;
}

int aes_128_cbc_decrypt_psa(const u8 *key, const u8 *iv, u8 *data, size_t data_len)
{
    psa_status_t status;
    psa_key_attributes_t attributes  = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id      = MBEDTLS_SVC_KEY_ID_INIT;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    psa_key_type_t key_type          = PSA_KEY_TYPE_AES;
    psa_algorithm_t alg              = PSA_ALG_CBC_NO_PADDING;
    size_t out_len                   = 0;

    if (data_len > SUPP_PSA_MAX_OUTPUT_SIZE)
    {
        printk("%s invalid input len %d", __func__, data_len);
        return -1;
    }

    supp_psa_set_attributes(&attributes, key_type, alg, PSA_KEY_USAGE_DECRYPT);

    status = psa_import_key(&attributes, key, SUPP_PSA_BLOCK_SIZE_128, &key_id);
    ASSERT_STATUS(status, PSA_SUCCESS);
    psa_reset_key_attributes(&attributes);

    status = psa_cipher_decrypt_setup(&operation, key_id, alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_cipher_set_iv(&operation, iv, PSA_CIPHER_IV_LENGTH(key_type, alg));
    ASSERT_STATUS(status, PSA_SUCCESS);

    memset(supp_psa_outbuf, 0x0, data_len);
    status = supp_psa_cipher_operation(&operation, data, data_len, PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type),
                                       supp_psa_outbuf, data_len, &out_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    memcpy(data, supp_psa_outbuf, out_len);
exit:
    psa_cipher_abort(&operation);
    if (key_id != MBEDTLS_SVC_KEY_ID_INIT)
    {
        psa_destroy_key(key_id);
    }
    return (int)status;
}

int aes_ctr_encrypt_psa(const u8 *key, size_t key_len, const u8 *nonce, u8 *data, size_t data_len)
{
    psa_status_t status;
    psa_key_attributes_t attributes  = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id      = MBEDTLS_SVC_KEY_ID_INIT;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    psa_key_type_t key_type          = PSA_KEY_TYPE_AES;
    psa_algorithm_t alg              = PSA_ALG_CTR;
    size_t out_len                   = 0;

    if (data_len > SUPP_PSA_MAX_OUTPUT_SIZE)
    {
        printk("%s invalid input len %d", __func__, data_len);
        return -1;
    }

    supp_psa_set_attributes(&attributes, key_type, alg, PSA_KEY_USAGE_ENCRYPT);

    status = psa_import_key(&attributes, key, key_len, &key_id);
    ASSERT_STATUS(status, PSA_SUCCESS);
    psa_reset_key_attributes(&attributes);

    status = psa_cipher_encrypt_setup(&operation, key_id, alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_cipher_set_iv(&operation, nonce, PSA_CIPHER_IV_LENGTH(key_type, alg));
    ASSERT_STATUS(status, PSA_SUCCESS);

    memset(supp_psa_outbuf, 0x0, data_len);
    status = supp_psa_cipher_operation(&operation, data, data_len, PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type),
                                       supp_psa_outbuf, data_len, &out_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    memcpy(data, supp_psa_outbuf, out_len);
exit:
    psa_cipher_abort(&operation);
    if (key_id != MBEDTLS_SVC_KEY_ID_INIT)
    {
        psa_destroy_key(key_id);
    }
    return (int)status;
}
#endif

#if defined(MBEDTLS_CMAC_C) || defined(CONFIG_PSA_WANT_ALG_CMAC)
int omac1_aes_vector_psa(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_mac_operation_t operation   = PSA_MAC_OPERATION_INIT;
    mbedtls_svc_key_id_t key_id     = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t alg             = PSA_ALG_CMAC;
    int i;
    size_t out_len = 0;

    switch (key_len)
    {
        case SUPP_PSA_BLOCK_SIZE_128:
            /* fall through */
        case SUPP_PSA_BLOCK_SIZE_192:
            /* fall through */
        case SUPP_PSA_BLOCK_SIZE_256:
            break;
        default:
            return -1;
    }

    supp_psa_set_attributes(&attributes, PSA_KEY_TYPE_AES, alg, PSA_KEY_USAGE_SIGN_MESSAGE);

    status = psa_import_key(&attributes, key, key_len, &key_id);
    ASSERT_STATUS(status, PSA_SUCCESS);
    psa_reset_key_attributes(&attributes);

    status = psa_mac_sign_setup(&operation, key_id, alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    for (i = 0; i < num_elem; i++)
    {
        status = psa_mac_update(&operation, addr[i], len[i]);
        ASSERT_STATUS(status, PSA_SUCCESS);
    }

    status = psa_mac_sign_finish(&operation, mac, PSA_MAC_LENGTH(PSA_KEY_TYPE_AES, key_len * 8, alg), &out_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    psa_mac_abort(&operation);
    if (key_id != MBEDTLS_SVC_KEY_ID_INIT)
    {
        psa_destroy_key(key_id);
    }
    return (int)status;
}
#endif

int md_vector_psa(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac, mbedtls_md_type_t md_type)
{
    psa_status_t status;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_algorithm_t alg            = PSA_ALG_NONE;
    int block_size;
    int i;
    size_t out_len = 0;

    supp_psa_get_hash_alg(md_type, &alg, &block_size);
    if (alg == PSA_ALG_NONE)
    {
        printk("md_vector unknown md type %d\r\n", md_type);
        return -1;
    }

    status = psa_hash_setup(&operation, alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    for (i = 0; i < num_elem; i++)
    {
        status = psa_hash_update(&operation, addr[i], len[i]);
        ASSERT_STATUS(status, PSA_SUCCESS);
    }

    status = psa_hash_finish(&operation, mac, block_size, &out_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    psa_hash_abort(&operation);
    return (int)status;
}

int hmac_vector_psa(const u8 *key,
                    size_t key_len,
                    size_t num_elem,
                    const u8 *addr[],
                    const size_t *len,
                    u8 *mac,
                    mbedtls_md_type_t md_type)
{
    psa_status_t status;
    psa_algorithm_t alg             = PSA_ALG_NONE;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_mac_operation_t operation   = PSA_MAC_OPERATION_INIT;
    mbedtls_svc_key_id_t key_id     = MBEDTLS_SVC_KEY_ID_INIT;
    int block_size;
    int i;
    size_t out_len = 0;

    supp_psa_get_hash_alg(md_type, &alg, &block_size);
    if (alg == PSA_ALG_NONE)
    {
        printk("hmac_vector unknown md type %d\r\n", md_type);
        return -1;
    }
    alg = PSA_ALG_HMAC(alg);

    supp_psa_set_attributes(&attributes, PSA_KEY_TYPE_HMAC, alg, PSA_KEY_USAGE_SIGN_MESSAGE);

    status = psa_import_key(&attributes, key, key_len, &key_id);
    ASSERT_STATUS(status, PSA_SUCCESS);
    psa_reset_key_attributes(&attributes);

    status = psa_mac_sign_setup(&operation, key_id, alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    for (i = 0; i < num_elem; i++)
    {
        status = psa_mac_update(&operation, addr[i], len[i]);
        ASSERT_STATUS(status, PSA_SUCCESS);
    }

    status = psa_mac_sign_finish(&operation, mac, PSA_MAC_LENGTH(PSA_KEY_TYPE_HMAC, key_len * 8, alg), &out_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    psa_mac_abort(&operation);
    if (key_id != MBEDTLS_SVC_KEY_ID_INIT)
    {
        psa_destroy_key(key_id);
    }
    return (int)status;
}

int pbkdf2_sha1_psa(mbedtls_md_type_t md_alg, const u8 *password, size_t plen,
                    const unsigned char *salt, size_t slen,
                    unsigned int iteration_count, uint32_t key_length,
                    unsigned char *output)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg             = PSA_ALG_NONE;
    mbedtls_svc_key_id_t key_id     = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    int block_size;

    supp_psa_get_hash_alg(md_alg, &alg, &block_size);
    if (alg == PSA_ALG_NONE) {
        printk("unknown md type %d\r\n", md_alg);
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&attributes, PSA_ALG_PBKDF2_HMAC(alg));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD);
    psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(plen));

    status = psa_import_key(&attributes, password, plen, &key_id);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_key_derivation_setup(&operation, PSA_ALG_PBKDF2_HMAC(alg));
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_key_derivation_input_integer(&operation, PSA_KEY_DERIVATION_INPUT_COST,
                                              iteration_count);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SALT, salt,
                                            slen);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_key_derivation_input_key(&operation, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                          key_id);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_key_derivation_output_bytes(&operation, output, key_length);
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    psa_key_derivation_abort(&operation);
    psa_destroy_key(key_id);
    return (int)status;
}

int supp_psa_crypto_init(void)
{
    int ret;

    ret = (int)psa_crypto_init();
    if (ret)
    {
        printk("supp_psa_crypto_init failed ret %d", ret);
        return ret;
    }

#ifdef CONFIG_WIFI_NM_WPA_SUPPLICANT_CRYPTO_TEST
    ret = crypto_module_tests();
    if (ret)
    {
        printk("crypto_module_tests failed ret %d", ret);
        return ret;
    }
#endif
    return ret;
}

void supp_psa_crypto_deinit(void)
{
    mbedtls_psa_crypto_free();
}
