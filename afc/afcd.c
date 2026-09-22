/*
 * Automated Frequency Coordination Daemon
 * Copyright (c) 2024, Lorenzo Bianconi <lorenzo@kernel.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <curl/curl.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "utils/common.h"

#define CURL_TIMEOUT	60
#define AFCD_SOCK	"afcd.sock"

struct curl_ctx {
	char *buf;
	size_t buf_len;
};

static volatile bool exiting;

static char *path = "/var/run";
static char *bearer_token;
static char *url;
static long port = 443;

enum afcd_tls_mode {
	AFCD_TLS12 = 0,
	AFCD_TLS12_MTLS,
	AFCD_TLS13,
	AFCD_TLS13_MTLS,
};
static enum afcd_tls_mode tls_mode = AFCD_TLS12;
static bool use_mtls;
static char *client_cert;	/* PEM or engine reference */
static char *client_key;	/* optional separate key */
static char *client_key_pass;	/* optional passphrase */
static char *cafile;		/* optional CA bundle override */


static size_t afcd_curl_cb_write(void *ptr, size_t size, size_t nmemb,
				 void *userdata)
{
	struct curl_ctx *ctx = userdata;
	char *buf;

	buf = os_realloc(ctx->buf, ctx->buf_len + size * nmemb + 1);
	if (!buf)
		return 0;

	ctx->buf = buf;
	os_memcpy(buf + ctx->buf_len, ptr, size * nmemb);
	buf[ctx->buf_len + size * nmemb] = '\0';
	ctx->buf_len += size * nmemb;

	return size * nmemb;
}


static int afcd_send_request(struct curl_ctx *ctx, unsigned char *request)
{
	struct curl_slist *headers = NULL, *tmp;
	int ret = CURLE_FAILED_INIT;
	CURL *curl;

	wpa_printf(MSG_DEBUG, "Sending AFC request to %s", url);

	curl = curl_easy_init();
	if (!curl)
		return -EINVAL;

	headers = curl_slist_append(headers, "Accept: application/json");
	if (!headers)
		goto out_easy_cleanup;

	tmp = curl_slist_append(headers, "Content-Type: application/json");
	if (!tmp)
		goto out_slist_free_all;
	headers = tmp;

	tmp = curl_slist_append(headers, "charset: utf-8");
	if (!tmp)
		goto out_slist_free_all;
	headers = tmp;

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_PORT, port);
	curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			 afcd_curl_cb_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, ctx);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcrp/0.1");
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) CURL_TIMEOUT);

	switch (tls_mode) {
	case AFCD_TLS12:
	case AFCD_TLS12_MTLS:
		curl_easy_setopt(curl, CURLOPT_SSLVERSION,
				 (long) CURL_SSLVERSION_TLSv1_2);
		break;
	case AFCD_TLS13:
	case AFCD_TLS13_MTLS:
		curl_easy_setopt(curl, CURLOPT_SSLVERSION,
				 (long) CURL_SSLVERSION_TLSv1_3);
		break;
	default:
		wpa_printf(MSG_ERROR, "Unknown TLS selection %d", tls_mode);
		goto out_slist_free_all;
	}

	if (use_mtls) {
		curl_easy_setopt(curl, CURLOPT_SSLCERT, client_cert);
		if (client_key)
			curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key);
		if (client_key_pass)
			curl_easy_setopt(curl, CURLOPT_KEYPASSWD,
					 client_key_pass);
	}

	if (bearer_token) {
		curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, bearer_token);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
	}

	if (cafile)
		curl_easy_setopt(curl, CURLOPT_CAINFO, cafile);

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);

	ret = curl_easy_perform(curl);
	if (ret != CURLE_OK)
		wpa_printf(MSG_ERROR, "curl_easy_perform failed: %s",
			   curl_easy_strerror(ret));

out_slist_free_all:
	curl_slist_free_all(headers);
out_easy_cleanup:
	curl_easy_cleanup(curl);

	return ret == CURLE_OK ? 0 : -EINVAL;
}


static void handle_term(int sig)
{
	wpa_printf(MSG_ERROR, "Received signal %d", sig);
	exiting = true;
}


static void usage(void)
{
	wpa_printf(MSG_ERROR,
		   "%s:\n"
		   "afcd -u<url> [-p<port>] [-t<token>] "
		   "[-S<12|13>] [-M] [-c<client-cert.pem>] "
		   "[-k<client-key.pem>] [-w<key-pass>] [-A<cafile>] "
		   "[-D<unix-sock dir>] [-P<PID file>] [-dB]",
		   __func__);
}


#define BUFSIZE		8192
static int afcd_server_run(void)
{
	size_t len = os_strlen(path) + 1 + os_strlen(AFCD_SOCK);
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
#ifdef __FreeBSD__
		.sun_len = sizeof(addr),
#endif /* __FreeBSD__ */
	};
	int sockfd, ret = 0;
	char *fname = NULL;
	unsigned char *buf;
	fd_set read_set;

	if (len >= sizeof(addr.sun_path))
		return -EINVAL;

	if (mkdir(path, S_IRWXU | S_IRWXG) < 0 && errno != EEXIST)
		return -EINVAL;

	buf = os_malloc(BUFSIZE);
	if (!buf)
		return -ENOMEM;

	fname = os_malloc(len + 1);
	if (!fname) {
		ret = -ENOMEM;
		goto free_buf;
	}

	os_snprintf(fname, len + 1, "%s/%s", path, AFCD_SOCK);
	os_strlcpy(addr.sun_path, fname, sizeof(addr.sun_path));

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		wpa_printf(MSG_ERROR, "Failed creating socket");
		ret = -errno;
		goto unlink;
	}

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		wpa_printf(MSG_ERROR, "Failed to bind socket");
		ret = -errno;
		goto close;
	}

	if (listen(sockfd, 10) < 0) {
		wpa_printf(MSG_ERROR, "Failed to listen on socket");
		ret = -errno;
		goto close;
	}

	curl_global_init(CURL_GLOBAL_ALL);
	FD_ZERO(&read_set);
	while (!exiting) {
		socklen_t addr_len = sizeof(addr);
		struct sockaddr_in6 c_addr;
		struct timeval timeout = {
			.tv_sec = 1,
		};
		struct curl_ctx ctx = {};
		int fd;

		FD_SET(sockfd, &read_set);
		if (select(sockfd + 1, &read_set, NULL, NULL, &timeout) < 0) {
			if (errno != EINTR) {
				wpa_printf(MSG_ERROR,
					   "Select failed on socket");
				ret = -errno;
				break;
			}
			continue;
		}

		if (!FD_ISSET(sockfd, &read_set))
			continue;

		fd = accept(sockfd, (struct sockaddr *)&c_addr,
			    &addr_len);
		if (fd < 0) {
			if (errno != EINTR) {
				wpa_printf(MSG_ERROR,
					   "Failed accepting connections");
				ret = -errno;
				break;
			}
			continue;
		}

		os_memset(buf, 0, BUFSIZE);
		if (recv(fd, buf, BUFSIZE - 1, 0) <= 0) {
			close(fd);
			continue;
		}
		buf[BUFSIZE - 1] = '\0';

		wpa_printf(MSG_DEBUG, "Received request: %s", buf);
		if (!afcd_send_request(&ctx, buf)) {
			wpa_printf(MSG_DEBUG, "Received reply: %s", ctx.buf);
			send(fd, ctx.buf, ctx.buf_len, MSG_NOSIGNAL);
			free(ctx.buf);
		}
		close(fd);
	}
	curl_global_cleanup();
close:
	close(sockfd);
unlink:
	unlink(fname);
	os_free(fname);
free_buf:
	os_free(buf);

	return ret;
}


int main(int argc, char **argv)
{
	bool daemonize = false;
	char *pid_file = NULL;
	int ret = -EINVAL;

	if (os_program_init())
		return -1;

	for (;;) {
		int c = getopt(argc, argv, "u:p:t:S:Mc:k:w:A:D:P:Bd");

		if (c < 0)
			break;

		switch (c) {
		case 'h':
			usage();
			ret = 0;
			goto out;
		case 'B':
			daemonize = true;
			break;
		case 'D':
			path = optarg;
			break;
		case 'P':
			os_free(pid_file);
			pid_file = os_rel2abs_path(optarg);
			break;
		case 'u':
			url = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'd':
			if (wpa_debug_level > 0)
				wpa_debug_level--;
			break;
		case 't':
			bearer_token = optarg;
			break;
		case 'S':
			if (!strcmp(optarg, "12"))
				tls_mode = AFCD_TLS12;
			else if (!strcmp(optarg, "13")) {
#ifndef CURL_SSLVERSION_TLSv1_3
				wpa_printf(MSG_ERROR,
					   "libcurl/SSL backend lacks TLSv1.3 support");
				goto out;
#endif /* CURL_SSLVERSION_TLSv1_3 */
				tls_mode = AFCD_TLS13;
			} else {
				wpa_printf(MSG_ERROR,
					   "Invalid TLS version '%s'", optarg);
				goto out;
			}
			break;
		case 'M':
			use_mtls = true;
			break;
		case 'c':
			client_cert = optarg;
			break;
		case 'k':
			client_key = optarg;
			break;
		case 'w':
			client_key_pass = optarg;
			break;
		case 'A':
			cafile = optarg;
			break;
		default:
			usage();
			goto out;
		}
	}

	if (!url) {
		usage();
		goto out;
	}

	if (use_mtls) {
		if (!client_cert) {
			wpa_printf(MSG_ERROR,
				   "mTLS requested but client certificate(-c) is missing");
			goto out;
		}
		if (tls_mode == AFCD_TLS12)
			tls_mode = AFCD_TLS12_MTLS;
		else if (tls_mode == AFCD_TLS13)
			tls_mode = AFCD_TLS13_MTLS;
	}

	if (daemonize && os_daemonize(pid_file)) {
		wpa_printf(MSG_ERROR, "daemon: %s", strerror(errno));
		goto out;
	}

	signal(SIGTERM, handle_term);
	signal(SIGINT, handle_term);

	ret = afcd_server_run();
out:
	if (pid_file)
		os_daemonize_terminate(pid_file);
	os_program_deinit();

	return ret;
}
