/*
 * SPDX-FileCopyrightText: 2020-2021 Espressif Systems (Shanghai) CO LTD
 * SPDX-FileCopyrightText: 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "utils/includes.h"
#include "utils/common.h"

#include "tls.h"
#include "crypto/sha1.h"
#include "crypto/md5.h"
#include "crypto/sha256.h"
#include "crypto/sha384.h"
#include "random.h"
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/build_info.h>
#include <assert.h>

#include <zephyr/random/random.h>

#define TLS_RANDOM_LEN 32
#define TLS_MASTER_SECRET_LEN 48
#define MAX_CIPHERSUITE 32

/* Throw a compilation error if basic requirements in mbedtls are not enabled */
#if !defined(MBEDTLS_SSL_TLS_C)
#error "TLS not enabled in mbedtls config"
#endif

#if !defined(MBEDTLS_SHA256_C)
#error "SHA256 is disabled in mbedtls config"
#endif

#if !defined(MBEDTLS_AES_C)
#error "AES support is disabled in mbedtls config"
#endif

uint32_t tls_instance_count;
struct tls_data
{
	/* Data for mbedlts */
	struct wpabuf *in_data;
	/* Data from mbedtls */
	struct wpabuf *out_data;
};

mbedtls_ssl_export_keys_t tls_connection_export_keys_cb;

typedef struct tls_context
{
	mbedtls_ssl_context ssl; /*!< TLS/SSL context */
	mbedtls_ctr_drbg_context
	    ctr_drbg;		 /*!< mbedTLS ctr drbg context structure */
	mbedtls_ssl_config conf; /*!< TLS/SSL config to be shared structures */
	mbedtls_x509_crt cacert; /*!< Container for X.509 CA certificate */
	mbedtls_x509_crt *cacert_ptr; /*!< Pointer to the cacert being used. */
	mbedtls_x509_crt
	    clientcert; /*!< Container for X.509 client certificate */
	mbedtls_pk_context clientkey; /*!< Private key of client certificate */
	int ciphersuite[MAX_CIPHERSUITE];
} tls_context_t;

struct tls_connection
{
	tls_context_t *tls;
	struct tls_data tls_io_data;
	unsigned char master_secret[TLS_MASTER_SECRET_LEN];
	unsigned char randbytes[2 * TLS_RANDOM_LEN];
	mbedtls_tls_prf_types tls_prf_type;
};

static int f_rng(void *p_rng, unsigned char *buf, size_t len)
{
	return random_get_bytes(buf, len);
}

static void tls_mbedtls_cleanup(tls_context_t *tls)
{
	if (!tls) {
		return;
	}
	tls->cacert_ptr = NULL;
	mbedtls_x509_crt_free(&tls->cacert);
	mbedtls_x509_crt_free(&tls->clientcert);
	mbedtls_pk_free(&tls->clientkey);
	mbedtls_ssl_config_free(&tls->conf);
	mbedtls_ctr_drbg_free(&tls->ctr_drbg);
	mbedtls_ssl_free(&tls->ssl);
}

static void tls_mbedtls_conn_delete(tls_context_t *tls)
{
	if (tls != NULL) {
		tls_mbedtls_cleanup(tls);
	}
}

static int tls_mbedtls_write(void *ctx, const unsigned char *buf, size_t len)
{
	struct tls_connection *conn = (struct tls_connection *)ctx;
	struct tls_data *data = &conn->tls_io_data;

	if (wpabuf_resize(&data->out_data, len) < 0)
		return 0;

	wpabuf_put_data(data->out_data, buf, len);

	return len;
}

static int tls_mbedtls_read(void *ctx, unsigned char *buf, size_t len)
{
	struct tls_connection *conn = (struct tls_connection *)ctx;
	struct tls_data *data = &conn->tls_io_data;
	struct wpabuf *local_buf;
	size_t data_len = len;

	if (data->in_data == NULL) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}

	if (len > wpabuf_len(data->in_data)) {
		wpa_printf(MSG_ERROR, "don't have suffient data\n");
		data_len = wpabuf_len(data->in_data);
	}

	os_memcpy(buf, wpabuf_head(data->in_data), data_len);
	/* adjust buffer */
	if (len < wpabuf_len(data->in_data)) {
		local_buf = wpabuf_alloc_copy(
		    (char *)wpabuf_head(data->in_data) + data_len,
		    wpabuf_len(data->in_data) - data_len);
		wpabuf_free(data->in_data);
		data->in_data = local_buf;
	} else {
		wpabuf_free(data->in_data);
		data->in_data = NULL;
	}

	return data_len;
}

static int
set_pki_context(tls_context_t *tls, const struct tls_connection_params *cfg)
{
	int ret = 0;

	if (cfg->client_cert_blob == NULL || cfg->private_key_blob == NULL) {
		wpa_printf(MSG_ERROR, "%s: config not correct", __func__);
		return -1;
	}

	mbedtls_x509_crt_init(&tls->clientcert);
	mbedtls_pk_init(&tls->clientkey);

	ret = mbedtls_x509_crt_parse(
	    &tls->clientcert, cfg->client_cert_blob, cfg->client_cert_blob_len);
	if (ret < 0) {
		wpa_printf(
		    MSG_ERROR, "mbedtls_x509_crt_parse returned -0x%x", -ret);
		return ret;
	}

	ret = mbedtls_pk_parse_key(
	    &tls->clientkey, cfg->private_key_blob, cfg->private_key_blob_len,
	    (const unsigned char *)cfg->private_key_passwd,
	    cfg->private_key_passwd ? os_strlen(cfg->private_key_passwd) : 0,
	    f_rng, NULL);
	if (ret < 0) {
		wpa_printf(
		    MSG_ERROR, "mbedtls_pk_parse_keyfile returned -0x%x", -ret);
		return ret;
	}

	ret = mbedtls_ssl_conf_own_cert(
	    &tls->conf, &tls->clientcert, &tls->clientkey);
	if (ret < 0) {
		wpa_printf(
		    MSG_ERROR, "mbedtls_ssl_conf_own_cert returned -0x%x",
		    -ret);
		return ret;
	}

	return 0;
}

static int
set_ca_cert(tls_context_t *tls, const unsigned char *cacert, size_t cacert_len)
{
	tls->cacert_ptr = &tls->cacert;
	mbedtls_x509_crt_init(tls->cacert_ptr);
	int ret = mbedtls_x509_crt_parse(tls->cacert_ptr, cacert, cacert_len);
	if (ret < 0) {
		wpa_printf(
		    MSG_ERROR, "mbedtls_x509_crt_parse returned -0x%x", -ret);
		return ret;
	}
	mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&tls->conf, tls->cacert_ptr, NULL);

	return 0;
}

#ifdef CONFIG_SUITEB192
static int tls_sig_hashes_for_suiteb[] = {
#if defined(MBEDTLS_SHA512_C)
    MBEDTLS_MD_SHA512, MBEDTLS_MD_SHA384,
#endif
    MBEDTLS_MD_NONE};

const mbedtls_x509_crt_profile suiteb_mbedtls_x509_crt_profile = {
#if defined(MBEDTLS_SHA512_C)
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) |
	MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512) |
#endif
	0,
    0xFFFFFFF, /* Any PK alg    */
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP384R1),
    1024,
};

static void tls_set_suiteb_config(tls_context_t *tls)
{
	const mbedtls_x509_crt_profile *crt_profile =
	    &suiteb_mbedtls_x509_crt_profile;
	mbedtls_ssl_conf_cert_profile(&tls->conf, crt_profile);
	mbedtls_ssl_conf_sig_hashes(&tls->conf, tls_sig_hashes_for_suiteb);
}
#endif

static int tls_sig_hashes_for_eap[] = {
#if defined(MBEDTLS_SHA512_C)
    MBEDTLS_MD_SHA512, MBEDTLS_MD_SHA384,
#endif
#if defined(MBEDTLS_SHA256_C)
    MBEDTLS_MD_SHA256, MBEDTLS_MD_SHA224,
#endif
#if defined(MBEDTLS_SHA1_C)
    MBEDTLS_MD_SHA1,
#endif
    MBEDTLS_MD_NONE};

const mbedtls_x509_crt_profile eap_mbedtls_x509_crt_profile = {
#if defined(MBEDTLS_SHA1_C)
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1) |
#endif
#if defined(MBEDTLS_SHA256_C)
	MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA224) |
	MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
#endif
#if defined(MBEDTLS_SHA512_C)
	MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) |
	MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512) |
#endif
	0,
    0xFFFFFFF, /* Any PK alg    */
    0xFFFFFFF, /* Any curve     */
    1024,
};

static void tls_enable_sha1_config(tls_context_t *tls)
{
	const mbedtls_x509_crt_profile *crt_profile =
	    &eap_mbedtls_x509_crt_profile;
	mbedtls_ssl_conf_cert_profile(&tls->conf, crt_profile);
	mbedtls_ssl_conf_sig_hashes(&tls->conf, tls_sig_hashes_for_eap);
}

static const int eap_ciphersuite_preference[] = {
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
#if defined(MBEDTLS_SHA512_C) && defined(MBEDTLS_GCM_C)
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
#endif
#if defined(MBEDTLS_CCM_C)
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
#endif
#if defined(MBEDTLS_GCM_C)
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
#endif

#if defined(MBEDTLS_GCM_C)
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
#endif
#if defined(MBEDTLS_CCM_C)
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
#endif
#if defined(MBEDTLS_CCM_C)
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8,
#endif
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8,

    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8,
#endif
#if defined(MBEDTLS_SHA512_C) && defined(MBEDTLS_GCM_C)
    MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
#endif
#if defined(MBEDTLS_CCM_C)
    MBEDTLS_TLS_RSA_WITH_AES_256_CCM,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
#endif
#if defined(MBEDTLS_CCM_C)
    MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8,
#endif

#if defined(MBEDTLS_GCM_C)
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
#endif
#if defined(MBEDTLS_CCM_C)
    MBEDTLS_TLS_RSA_WITH_AES_128_CCM,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
#endif
#if defined(MBEDTLS_GCM_C)
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
#endif
#if defined(MBEDTLS_GCM_C)
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
#endif
#if defined(MBEDTLS_CCM_C)
    MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8,
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
#if defined(MBEDTLS_GCM_C)
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
#endif
/* The PSK suites */
#if defined(MBEDTLS_GCM_C)
    MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,
#endif
#if defined(MBEDTLS_CCM_C)
    MBEDTLS_TLS_PSK_WITH_AES_256_CCM,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA,
#endif
#if defined(MBEDTLS_CCM_C)
    MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8,
#endif

#if defined(MBEDTLS_GCM_C)
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
#endif
#if defined(MBEDTLS_CCM_C)
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA,
#endif
#if defined(MBEDTLS_CCM_C)
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,
#endif
#endif

#if 0
	/* 3DES suites */
	MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	MBEDTLS_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
	MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	MBEDTLS_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
	MBEDTLS_TLS_PSK_WITH_3DES_EDE_CBC_SHA,
#endif
#if defined(MBEDTLS_ARC4_C)
    /* RC4 suites */
    MBEDTLS_TLS_DHE_PSK_WITH_RC4_128_SHA, MBEDTLS_TLS_RSA_WITH_RC4_128_SHA,
    MBEDTLS_TLS_RSA_WITH_RC4_128_MD5, MBEDTLS_TLS_RSA_PSK_WITH_RC4_128_SHA,
    MBEDTLS_TLS_PSK_WITH_RC4_128_SHA,
#endif
    0};

#ifdef CONFIG_SUITEB192
static const int suiteb_rsa_ciphersuite_preference[] = {
#if defined(MBEDTLS_GCM_C)
#if defined(MBEDTLS_SHA512_C)
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
#endif
#endif
    0};

static const int suiteb_ecc_ciphersuite_preference[] = {
#if defined(MBEDTLS_GCM_C)
#if defined(MBEDTLS_SHA512_C)
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
#endif
#endif
    0};
static const int suiteb_ciphersuite_preference[] = {
#if defined(MBEDTLS_GCM_C)
#if defined(MBEDTLS_SHA512_C)
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
#endif
#endif
    0};
#endif

static void
tls_set_ciphersuite(const struct tls_connection_params *cfg, tls_context_t *tls)
{
	/* Only set ciphersuite if cert's key length is high or ciphersuites are
	 * set by user */
#ifdef CONFIG_SUITEB192
	if (cfg->flags & TLS_CONN_SUITEB) {
		/* cipher suites will be set based on certificate */
		mbedtls_pk_type_t pk_alg = mbedtls_pk_get_type(&tls->clientkey);
		if (pk_alg == MBEDTLS_PK_RSA ||
		    pk_alg == MBEDTLS_PK_RSASSA_PSS) {
			mbedtls_ssl_conf_ciphersuites(
			    &tls->conf, suiteb_rsa_ciphersuite_preference);
		} else if (
		    pk_alg == MBEDTLS_PK_ECDSA || pk_alg == MBEDTLS_PK_ECKEY ||
		    pk_alg == MBEDTLS_PK_ECKEY_DH) {
			mbedtls_ssl_conf_ciphersuites(
			    &tls->conf, suiteb_ecc_ciphersuite_preference);
		} else {
			mbedtls_ssl_conf_ciphersuites(
			    &tls->conf, suiteb_ciphersuite_preference);
		}
	} else
#endif
	    if (tls->ciphersuite[0]) {
		mbedtls_ssl_conf_ciphersuites(&tls->conf, tls->ciphersuite);
	} else if (
	    mbedtls_pk_get_bitlen(&tls->clientkey) > 2048 ||
	    (tls->cacert_ptr &&
	     mbedtls_pk_get_bitlen(&tls->cacert_ptr->pk) >
		 2048)) {
		mbedtls_ssl_conf_ciphersuites(
		    &tls->conf, eap_ciphersuite_preference);
	}
}

static int
parse_certs(const struct tls_connection_params *cfg, tls_context_t *tls)
{
	int ret = 0;

#ifdef CONFIG_MBEDTLS_FS_IO
	if (cfg->ca_cert) {
		tls->cacert_ptr = &tls->cacert;
		mbedtls_x509_crt_init(tls->cacert_ptr);

		ret = mbedtls_x509_crt_parse_file(&tls->cacert, cfg->ca_cert);
		if (ret < 0) {
			wpa_printf(
			    MSG_ERROR,
			    "mbedtls_x509_crt_parse_der failed -0x%x", -ret);
			return -1;
		}

		mbedtls_ssl_conf_authmode(
		    &tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_ca_chain(&tls->conf, tls->cacert_ptr, NULL);
		wpa_printf(MSG_ERROR, "Loaded CA cert: %s\n", cfg->ca_cert);

	} else
#endif
	    if (cfg->ca_cert_blob != NULL) {
		ret =
		    set_ca_cert(tls, cfg->ca_cert_blob, cfg->ca_cert_blob_len);
		if (ret != 0) {
			return ret;
		}
		mbedtls_ssl_conf_ca_chain(&tls->conf, tls->cacert_ptr, NULL);
	} else {
		mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE);
	}

#ifdef CONFIG_MBEDTLS_FS_IO
	if (cfg->client_cert && cfg->private_key) {
		mbedtls_x509_crt_init(&tls->clientcert);
		ret = mbedtls_x509_crt_parse_file(
		    &tls->clientcert, cfg->client_cert);
		if (ret < 0) {
			wpa_printf(
			    MSG_ERROR,
			    "mbedtls_x509_crt_parse_der failed -0x%x", -ret);
			return -1;
		}
		wpa_printf(
		    MSG_ERROR, "Loaded Client cert: %s\n", cfg->client_cert);

		mbedtls_pk_init(&tls->clientkey);
		ret = mbedtls_pk_parse_keyfile(
		    &tls->clientkey, cfg->private_key, cfg->private_key_passwd,
		    f_rng, NULL);
		if (ret < 0) {
			wpa_printf(
			    MSG_ERROR, "mbedtls_pk_parse_key failed -0x%x",
			    -ret);
			return -1;
		}
		wpa_printf(
		    MSG_ERROR, "Loaded private key: %s\n", cfg->private_key);

		ret = mbedtls_ssl_conf_own_cert(
		    &tls->conf, &tls->clientcert, &tls->clientkey);
		if (ret < 0) {
			wpa_printf(
			    MSG_ERROR,
			    "mbedtls_ssl_conf_own_cert returned -0x%x", -ret);
			return ret;
		}
		wpa_printf(MSG_ERROR, "Loaded client and key\n");

	} else
#endif
	    if (cfg->client_cert_blob != NULL &&
		cfg->private_key_blob != NULL) {
		ret = set_pki_context(tls, cfg);
		if (ret != 0) {
			wpa_printf(
			    MSG_ERROR, "Failed to set client pki context");
			return ret;
		}
	}

	return 0;
}

static int
set_client_config(const struct tls_connection_params *cfg, tls_context_t *tls)
{
	int ret = 0;
	int preset = MBEDTLS_SSL_PRESET_DEFAULT;
	assert(cfg != NULL);
	assert(tls != NULL);

#ifdef CONFIG_SUITEB192
	if (cfg->flags & TLS_CONN_SUITEB)
		preset = MBEDTLS_SSL_PRESET_SUITEB;
#endif
	ret = mbedtls_ssl_config_defaults(
	    &tls->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
	    preset);
	if (ret != 0) {
		wpa_printf(
		    MSG_ERROR, "mbedtls_ssl_config_defaults returned -0x%x",
		    -ret);
		return ret;
	}

	if (preset != MBEDTLS_SSL_PRESET_SUITEB) {
		/* Enable SHA1 support since it's not enabled by default in
		 * mbedtls */
		tls_enable_sha1_config(tls);
#ifdef CONFIG_SUITEB192
	} else {
		tls_set_suiteb_config(tls);
#endif
	}
	wpa_printf(
	    MSG_ERROR, ": mbedtls_ssl_config_defaults: ciphersuite: %s\n",
	    mbedtls_ssl_get_ciphersuite(&tls->ssl));

	wpa_printf(MSG_ERROR, ": CA cert: %s\n", cfg->ca_cert);
	wpa_printf(MSG_ERROR, ": Client cert: %s\n", cfg->client_cert);
	wpa_printf(MSG_ERROR, ": Client key: %s\n", cfg->private_key);

	if ((ret = parse_certs(cfg, tls))) {
		wpa_printf(MSG_ERROR, "Failed to load certs: %d\n", ret);
		return ret;
	}
	wpa_printf(MSG_INFO, "Loaded certs\n");

	/* Usages of default ciphersuites can take a lot of time on low end
	 * device and can cause watchdog. Enabling the ciphers which are secured
	 * enough but doesn't take that much processing power */
	tls_set_ciphersuite(cfg, tls);

	return 0;
}

static int tls_ctr_drbg_random(void *ctx, unsigned char *buf, size_t len)
{
	ARG_UNUSED(ctx);

#if defined(CONFIG_ENTROPY_HAS_DRIVER)
	return sys_csrand_get(buf, len);
#else
	sys_rand_get(buf, len);

	return 0;
#endif
}

static int tls_create_mbedtls_handle(
    const struct tls_connection_params *params, tls_context_t *tls)
{
	int ret = 0;

	assert(params != NULL);
	assert(tls != NULL);

	mbedtls_ssl_init(&tls->ssl);
	mbedtls_ssl_config_init(&tls->conf);

	ret = set_client_config(params, tls);
	if (ret != 0) {
		wpa_printf(MSG_ERROR, "Failed to set client configurations");
		goto exit;
	}


	mbedtls_ssl_conf_rng(
	    &tls->conf, tls_ctr_drbg_random, NULL);

	ret = mbedtls_ssl_setup(&tls->ssl, &tls->conf);
	if (ret != 0) {
		wpa_printf(MSG_ERROR, "mbedtls_ssl_setup returned -0x%x", -ret);
		goto exit;
	}
#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
	/* Disable BEAST attack countermeasures for Windows 2008
	 * interoperability */
	mbedtls_ssl_conf_cbc_record_splitting(
	    &tls->conf, MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED);
#endif

	return 0;

exit:
	tls_mbedtls_cleanup(tls);
	return ret;
}

void *tls_init(const struct tls_config *conf)
{
	tls_instance_count++;
	return &tls_instance_count;
}

void tls_deinit(void *tls_ctx) { tls_instance_count--; }

struct tls_connection *tls_connection_init(void *tls_ctx)
{
	struct tls_connection *conn = os_zalloc(sizeof(*conn));
	if (!conn) {
		wpa_printf(
		    MSG_ERROR, "TLS: Failed to allocate connection memory");
		return NULL;
	}

	return conn;
}

void tls_connection_deinit(void *tls_ctx, struct tls_connection *conn)
{
	/* case: tls init failed */
	if (!conn) {
		return;
	}
	/* Free ssl ctx and data */
	tls_mbedtls_conn_delete((tls_context_t *)conn->tls);
	os_free(conn->tls);
	conn->tls = NULL;
	/* Data in in ssl ctx, free connection */
	os_free(conn);
}

int tls_get_errors(void *tls_ctx) { return 0; }

int tls_connection_established(void *tls_ctx, struct tls_connection *conn)
{
	mbedtls_ssl_context *ssl = &conn->tls->ssl;

	if (ssl->MBEDTLS_PRIVATE(state) == MBEDTLS_SSL_HANDSHAKE_OVER) {
		return 1;
	}

	return 0;
}

int tls_global_set_verify(void *tls_ctx, int check_crl, int strict)
{
	wpa_printf(MSG_INFO, "TLS: global settings are not supported");
	return -1;
}

int tls_connection_set_verify(
    void *tls_ctx, struct tls_connection *conn, int verify_peer,
    unsigned int flags, const u8 *session_ctx, size_t session_ctx_len)
{
	wpa_printf(MSG_INFO, "TLS: tls_connection_set_verify not supported");
	return -1;
}

struct wpabuf *tls_connection_handshake(
    void *tls_ctx, struct tls_connection *conn, const struct wpabuf *in_data,
    struct wpabuf **appl_data)
{
	tls_context_t *tls = conn->tls;
	int ret = 0;

	/* data freed by sender */
	conn->tls_io_data.out_data = NULL;
	if (wpabuf_len(in_data)) {
		conn->tls_io_data.in_data = wpabuf_dup(in_data);
	}

	/* Multiple reads */
	while (tls->ssl.MBEDTLS_PRIVATE(state) != MBEDTLS_SSL_HANDSHAKE_OVER) {
		ret = mbedtls_ssl_handshake_step(&tls->ssl);

		if (ret < 0)
			break;
	}
	if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ) {
		wpa_printf(MSG_INFO, "%s: ret is %d", __func__, ret);
		goto end;
	}

	if (!conn->tls_io_data.out_data) {
		wpa_printf(
		    MSG_INFO,
		    "application data is null, adding one byte for ack");
		u8 *dummy = os_zalloc(1);
		conn->tls_io_data.out_data = wpabuf_alloc_ext_data(dummy, 0);
	}

end:
	return conn->tls_io_data.out_data;
}

struct wpabuf *tls_connection_server_handshake(
    void *tls_ctx, struct tls_connection *conn, const struct wpabuf *in_data,
    struct wpabuf **appl_data)
{
	wpa_printf(MSG_ERROR, "%s: not supported %d", __func__, __LINE__);
	return NULL;
}

struct wpabuf *tls_connection_encrypt(
    void *tls_ctx, struct tls_connection *conn, const struct wpabuf *in_data)
{
	/* Reset dangling pointer */
	conn->tls_io_data.out_data = NULL;

	ssize_t ret = mbedtls_ssl_write(
	    &conn->tls->ssl, (unsigned char *)wpabuf_head(in_data),
	    wpabuf_len(in_data));

	if (ret < wpabuf_len(in_data)) {
		wpa_printf(
		    MSG_ERROR, "%s:%d, not able to write whole data", __func__,
		    __LINE__);
	}

	return conn->tls_io_data.out_data;
}

struct wpabuf *tls_connection_decrypt(
    void *tls_ctx, struct tls_connection *conn, const struct wpabuf *in_data)
{
	unsigned char buf[1200];
	int ret = 0;
	conn->tls_io_data.in_data = wpabuf_dup(in_data);
	ret = mbedtls_ssl_read(&conn->tls->ssl, buf, 1200);
	if (ret < 0) {
		wpa_printf(
		    MSG_ERROR, "%s:%d, not able to write whole data", __func__,
		    __LINE__);
		return NULL;
	}

	struct wpabuf *out = wpabuf_alloc_copy(buf, ret);

	return out;
}

int tls_connection_resumed(void *tls_ctx, struct tls_connection *conn)
{
	if (conn && conn->tls) {
		mbedtls_ssl_session *session = NULL;

		// If we have a session, then its resumed
		mbedtls_ssl_get_session(&conn->tls->ssl, session);

		if (session) {
			return 1;
		}
	}

	return 0;
}

/* cipher array should contain cipher number in mbedtls num as per IANA
 * Please see cipherlist is u8, therefore only initial ones are supported */
int tls_connection_set_cipher_list(
    void *tls_ctx, struct tls_connection *conn, u8 *ciphers)
{
	int i = 0;

	while (*ciphers != 0 && i < MAX_CIPHERSUITE) {
		conn->tls->ciphersuite[i] = ciphers[i];
		i++;
	}
	return 0;
}

int tls_get_version(
    void *tls_ctx, struct tls_connection *conn, char *buf, size_t buflen)
{
	const char *name;

	if (conn == NULL) {
		return -1;
	}

	name = mbedtls_ssl_get_version(&conn->tls->ssl);
	if (name == NULL) {
		return -1;
	}

	os_strlcpy(buf, name, buflen);

	return 0;
}

int tls_get_library_version(char *buf, size_t buf_len)
{

	return os_snprintf(buf, buf_len, "MbedTLS build=test run=test");
}

// Lifted from https://stackoverflow.com/a/47117431
char *strremove(char *str, const char *sub)
{
	char *p, *q, *r;
	if (*sub && (q = r = os_strstr(str, sub)) != NULL) {
		size_t len = os_strlen(sub);
		while ((r = os_strstr(p = r + len, sub)) != NULL) {
			os_memmove(q, p, r - p);
			q += r - p;
		}
		os_memmove(q, p, strlen(p) + 1);
	}
	return str;
}

// Lifted from: https://stackoverflow.com/a/779960
// You must free the result if result is non-NULL.
char *str_replace(char *orig, char *rep, char *with)
{
	char *result;  // the return string
	char *ins;     // the next insert point
	char *tmp;     // varies
	int len_rep;   // length of rep (the string to remove)
	int len_with;  // length of with (the string to replace rep with)
	int len_front; // distance between rep and end of last rep
	int count;     // number of replacements

	// sanity checks and initialization
	if (!orig || !rep)
		return NULL;
	len_rep = strlen(rep);
	if (len_rep == 0)
		return NULL; // empty rep causes infinite loop during count
	if (!with)
		with = "";
	len_with = strlen(with);

	// count the number of replacements needed
	ins = orig;
	for (count = 0; (tmp = strstr(ins, rep)); ++count) {
		ins = tmp + len_rep;
	}

	tmp = result = os_zalloc(strlen(orig) + (len_with - len_rep) * count + 1);

	if (!result)
		return NULL;

	// first time through the loop, all the variable are set correctly
	// from here on,
	//    tmp points to the end of the result string
	//    ins points to the next occurrence of rep in orig
	//    orig points to the remainder of orig after "end of rep"
	while (count--) {
		ins = strstr(orig, rep);
		len_front = ins - orig;
		tmp = strncpy(tmp, orig, len_front) + len_front;
		tmp = strcpy(tmp, with) + len_with;
		orig += len_front + len_rep; // move to next "end of rep"
	}
	strcpy(tmp, orig);
	return result;
}

int tls_get_cipher(
    void *tls_ctx, struct tls_connection *conn, char *buf, size_t buflen)
{
	const char *name;
	if (conn == NULL) {
		return -1;
	}

	name = mbedtls_ssl_get_ciphersuite(&conn->tls->ssl);
	if (name == NULL) {
		return -1;
	}

	os_strlcpy(buf, name, buflen);

	// Translate to common format for hwsim tests to pass
	strremove(buf, "TLS-");
	strremove(buf, "WITH-");
	char *tmp = str_replace(buf, "AES-", "AES");
	os_memcpy(buf, tmp, buflen);
	os_free(tmp);

	return 0;
}

int tls_connection_enable_workaround(void *tls_ctx, struct tls_connection *conn)
{
	return -1;
}

int tls_connection_get_failed(void *tls_ctx, struct tls_connection *conn)
{
	return 0;
}

int tls_connection_get_read_alerts(void *tls_ctx, struct tls_connection *conn)
{
	return 0;
}

int tls_connection_get_write_alerts(void *tls_ctx, struct tls_connection *conn)
{
	return 0;
}

void tls_connection_set_success_data(
    struct tls_connection *conn, struct wpabuf *data)
{}

void tls_connection_set_success_data_resumed(struct tls_connection *conn) {}

const struct wpabuf *
tls_connection_get_success_data(struct tls_connection *conn)
{
	return NULL;
}

void tls_connection_remove_session(struct tls_connection *conn) {}

char *tls_connection_peer_serial_num(void *tls_ctx, struct tls_connection *conn)
{
	return NULL;
}

int tls_connection_set_params(
    void *tls_ctx, struct tls_connection *conn,
    const struct tls_connection_params *params)
{
	int ret = 0;

	wpa_printf(
	    MSG_ERROR, " client_cert 4is %s, %p", params->client_cert, params);

	tls_context_t *tls = (tls_context_t *)os_zalloc(sizeof(tls_context_t));

	if (!tls) {
		wpa_printf(MSG_ERROR, "failed to allocate tls context");
		return -1;
	}
	if (!params) {
		wpa_printf(MSG_ERROR, "configuration is null");
		ret = -1;
		goto err;
	}
	// assert(params->client_cert != NULL);

	ret = tls_create_mbedtls_handle(params, tls);
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "failed to create ssl handle");
		goto err;
	}
	mbedtls_ssl_set_bio(
	    &tls->ssl, conn, tls_mbedtls_write, tls_mbedtls_read, NULL);
	conn->tls = (tls_context_t *)tls;

	mbedtls_ssl_set_export_keys_cb(
	    &conn->tls->ssl, tls_connection_export_keys_cb, conn);

	return ret;
err:
	os_free(tls);
	return ret;
}

int tls_global_set_params(
    void *tls_ctx, const struct tls_connection_params *params)
{
	wpa_printf(MSG_INFO, "TLS: Global parameters not supported");
	return -1;
}

int tls_connection_set_session_ticket_cb(
    void *tls_ctx, struct tls_connection *conn, tls_session_ticket_cb cb,
    void *ctx)
{
	wpa_printf(MSG_ERROR, "TLS: %s not supported", __func__);
	return -1;
}

void tls_connection_export_keys_cb(
    void *p_expkey, mbedtls_ssl_key_export_type secret_type,
    const unsigned char *secret, size_t secret_len,
    const unsigned char client_random[32],
    const unsigned char server_random[32], mbedtls_tls_prf_types tls_prf_type)

{
	struct tls_connection *conn = p_expkey;

	os_memcpy(conn->randbytes, client_random, TLS_RANDOM_LEN);
	os_memcpy(
	    conn->randbytes + TLS_RANDOM_LEN, server_random, TLS_RANDOM_LEN);
	os_memcpy(conn->master_secret, secret, secret_len);
	conn->tls_prf_type = tls_prf_type;
}
static int tls_connection_prf(
    void *tls_ctx, struct tls_connection *conn, const char *label,
    int server_random_first, u8 *out, size_t out_len)
{
	int ret = 0;
	u8 seed[2 * TLS_RANDOM_LEN];
	mbedtls_ssl_context *ssl = &conn->tls->ssl;

	if (!ssl || !conn) {
		wpa_printf(
		    MSG_ERROR, "TLS: %s, connection  info is null", __func__);
		return -1;
	}
	if (ssl->MBEDTLS_PRIVATE(state) != MBEDTLS_SSL_HANDSHAKE_OVER) {
		wpa_printf(
		    MSG_ERROR, "TLS: %s, incorrect tls state=%d", __func__,
		    ssl->MBEDTLS_PRIVATE(state));
		return -1;
	}

	if (server_random_first) {
		os_memcpy(
		    seed, conn->randbytes + TLS_RANDOM_LEN, TLS_RANDOM_LEN);
		os_memcpy(
		    seed + TLS_RANDOM_LEN, conn->randbytes, TLS_RANDOM_LEN);
	} else {
		os_memcpy(seed, conn->randbytes, 2 * TLS_RANDOM_LEN);
	}

	wpa_hexdump_key(MSG_MSGDUMP, "random", seed, 2 * TLS_RANDOM_LEN);
	wpa_hexdump_key(
	    MSG_MSGDUMP, "master", conn->master_secret, TLS_MASTER_SECRET_LEN);

	if (conn->tls_prf_type == MBEDTLS_SSL_TLS_PRF_SHA384) {
		ret = tls_prf_sha384(
		    conn->master_secret, TLS_MASTER_SECRET_LEN, label, seed,
		    2 * TLS_RANDOM_LEN, out, out_len);
	} else if (conn->tls_prf_type == MBEDTLS_SSL_TLS_PRF_SHA256) {
		ret = tls_prf_sha256(
		    conn->master_secret, TLS_MASTER_SECRET_LEN, label, seed,
		    2 * TLS_RANDOM_LEN, out, out_len);
	} else {
		ret = tls_prf_sha1_md5(
		    conn->master_secret, TLS_MASTER_SECRET_LEN, label, seed,
		    2 * TLS_RANDOM_LEN, out, out_len);
	}

	if (ret < 0) {
		wpa_printf(MSG_ERROR, "prf failed, ret=%d\n", ret);
	}
	wpa_hexdump_key(MSG_MSGDUMP, "key", out, out_len);

	return ret;
}

int tls_connection_export_key(
    void *tls_ctx, struct tls_connection *conn, const char *label,
    const u8 *context, size_t context_len, u8 *out, size_t out_len)
{
	return tls_connection_prf(tls_ctx, conn, label, 0, out, out_len);
}

int tls_connection_get_eap_fast_key(
    void *tls_ctx, struct tls_connection *conn, u8 *out, size_t out_len)
{
	wpa_printf(
	    MSG_INFO, "TLS: tls_connection_get_eap_fast_key not supported, "
		      "please unset mbedtls crypto and try again");
	return -1;
}

int tls_connection_client_hello_ext(
    void *tls_ctx, struct tls_connection *conn, int ext_type, const u8 *data,
    size_t data_len)
{
	wpa_printf(
	    MSG_INFO, "TLS: tls_connection_client_hello_ext not supported, "
		      "please unset mbedtls crypto and try again");
	return -1;
}

int tls_connection_shutdown(void *tls_ctx, struct tls_connection *conn)
{
	if (conn->tls_io_data.in_data) {
		wpabuf_free(conn->tls_io_data.in_data);
	}
	conn->tls_io_data.in_data = NULL;

	/* outdata may have dangling pointer */
	conn->tls_io_data.out_data = NULL;

	return mbedtls_ssl_session_reset(&conn->tls->ssl);
}

int tls_connection_get_random(
    void *tls_ctx, struct tls_connection *conn, struct tls_random *data)
{
	mbedtls_ssl_context *ssl = &conn->tls->ssl;

	os_memset(data, 0, sizeof(*data));
	if (ssl->MBEDTLS_PRIVATE(state) == MBEDTLS_SSL_CLIENT_HELLO) {
		return -1;
	}

	data->client_random = conn->randbytes;
	data->client_random_len = TLS_RANDOM_LEN;

	if (ssl->MBEDTLS_PRIVATE(state) != MBEDTLS_SSL_SERVER_HELLO) {
		data->server_random = conn->randbytes + TLS_RANDOM_LEN;
		data->server_random_len = TLS_RANDOM_LEN;
	}

	return 0;
}
