/*
 * Hostapd - command line interface for hostapd daemon
 *                  for Zephyr (based on hostapd_cli.c)
 * Copyright (c) 2004-2022, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2024, NXP
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "includes.h"

#include "common/cli.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/edit.h"
#include "utils/list.h"
#include "ap/hostapd.h"
#include "ctrl_iface.h"
#include "common/version.h"
#include "common/ieee802_11_defs.h"
#include "supp_main.h"
#include "ctrl_iface_zephyr.h"
#include "hostapd_cli_zephyr.h"

#include <zephyr/zvfs/eventfd.h>

#define CMD_BUF_LEN  1024
#define MAX_CMD_SIZE 512
#define MAX_ARGS 32

static struct wpa_ctrl *hapd_ctrl_conn = NULL;

static inline uint16_t supp_strlen(const char *str)
{
	return str == NULL ? 0U : (uint16_t)strlen(str);
}

static char make_argv(char **ppcmd, uint8_t c)
{
	char *cmd = *ppcmd;
	char quote = 0;

	while (1) {
		c = *cmd;

		if (c == '\0') {
			break;
		}

		if (quote == c) {
			memmove(cmd, cmd + 1, supp_strlen(cmd));
			quote = 0;
			continue;
		}

		if (quote && c == '\\') {
			char t = *(cmd + 1);

			if (t == quote) {
				memmove(cmd, cmd + 1,
						supp_strlen(cmd));
				cmd += 1;
				continue;
			}

			if (t == '0') {
				uint8_t i;
				uint8_t v = 0U;

				for (i = 2U; i < (2 + 3); i++) {
					t = *(cmd + i);

					if (t >= '0' && t <= '7') {
						v = (v << 3) | (t - '0');
					} else {
						break;
					}
				}

				if (i > 2) {
					memmove(cmd, cmd + (i - 1),
						supp_strlen(cmd) - (i - 2));
					*cmd++ = v;
					continue;
				}
			}

			if (t == 'x') {
				uint8_t i;
				uint8_t v = 0U;

				for (i = 2U; i < (2 + 2); i++) {
					t = *(cmd + i);

					if (t >= '0' && t <= '9') {
						v = (v << 4) | (t - '0');
					} else if ((t >= 'a') &&
						   (t <= 'f')) {
						v = (v << 4) | (t - 'a' + 10);
					} else if ((t >= 'A') && (t <= 'F')) {
						v = (v << 4) | (t - 'A' + 10);
					} else {
						break;
					}
				}

				if (i > 2) {
					memmove(cmd, cmd + (i - 1),
						supp_strlen(cmd) - (i - 2));
					*cmd++ = v;
					continue;
				}
			}
		}

		if (!quote && isspace((int) c)) {
			break;
		}

		cmd += 1;
	}
	*ppcmd = cmd;

	return quote;
}

char hostapd_make_argv(size_t *argc, const char **argv, char *cmd,
		       uint8_t max_argc)
{
	char quote = 0;
	char c;

	*argc = 0;
	do {
		c = *cmd;
		if (c == '\0') {
			break;
		}

		if (isspace((int) c)) {
			*cmd++ = '\0';
			continue;
		}

		argv[(*argc)++] = cmd;
		if (*argc == max_argc) {
			break;
		}
		quote = make_argv(&cmd, c);
	} while (true);

	return quote;
}

void hostapd_cli_msg_cb(char *msg, size_t len)
{
	wpa_printf(MSG_INFO, "%s", msg);
}

static int _wpa_ctrl_command(struct wpa_ctrl *ctrl, const char *cmd, int print, char *resp)
{
	char buf[CMD_BUF_LEN] = { 0 };
	size_t len;
	int ret;

	if (hapd_ctrl_conn == NULL) {
		wpa_printf(MSG_ERROR, "Not connected to hostapd - command dropped.");
		return -1;
	}

	if (ifname_prefix) {
		os_snprintf(buf, sizeof(buf), "IFNAME=%s %s", ifname_prefix, cmd);
		buf[sizeof(buf) - 1] = '\0';
		cmd = buf;
	}

	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, cmd, os_strlen(cmd), buf, &len, hostapd_cli_msg_cb);
	if (ret == -2) {
		wpa_printf(MSG_ERROR, "'%s' command timed out.", cmd);
		return -2;
	} else if (ret < 0) {
		wpa_printf(MSG_ERROR, "'%s' command failed.", cmd);
		return -1;
	}

	if (resp && len > 0) {
		os_memcpy(resp, buf, len);
		if (len > 1 && resp[len - 1] == '\n') {
			/* Remove the LF */
			resp[len - 1] = '\0';
		} else {
			resp[len] = '\0';
		}
		if (strncmp(resp, "FAIL", 4) == 0)
			return -3;
	}

	if (print) {
		buf[len] = '\0';
		if (buf[0] != '\0')
			wpa_printf(MSG_INFO, "%s", buf);
	}

	return 0;
}

int hostapd_ctrl_command(struct wpa_ctrl *ctrl, const char *cmd)
{
	return _wpa_ctrl_command(ctrl, cmd, 0, NULL);
}

int hostapd_ctrl_command_interactive(struct wpa_ctrl *ctrl, const char *cmd)
{
	return _wpa_ctrl_command(ctrl, cmd, 1, NULL);
}

int zephyr_hostapd_cli_cmd_resp(const char *cmd, char *resp)
{
	return _wpa_ctrl_command(hapd_ctrl_conn, cmd, 1, resp);
}

int zephyr_hostapd_ctrl_zephyr_cmd(int argc, const char *argv[])
{
	return hostapd_request(hapd_ctrl_conn, argc , (char **) argv);
}

int zephyr_hostapd_cli_cmd_v(const char *fmt, ...)
{
	va_list cmd_args;
	int argc;
	const char *argv[MAX_ARGS];
	char cmd[MAX_CMD_SIZE];

	va_start(cmd_args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, cmd_args);
	va_end(cmd_args);

	(void)hostapd_make_argv(&argc, &argv[0], cmd, MAX_ARGS);

	wpa_printf(MSG_DEBUG, "Calling hostapd_cli: %s, argc: %d", cmd, argc);
	for (int i = 0; i < argc; i++)
		wpa_printf(MSG_DEBUG, "argv[%d]: %s", i, argv[i]);

	return zephyr_hostapd_ctrl_zephyr_cmd(argc, argv);
}

static int hostapd_cli_open_connection(struct hostapd_data *hapd)
{
	if (!hapd_ctrl_conn) {
		hapd_ctrl_conn = wpa_ctrl_open(hapd->recv_sock, &hapd->recv_fifo,
					       hapd->send_sock, &hapd->send_fifo);
		if (hapd_ctrl_conn == NULL) {
			wpa_printf(MSG_ERROR, "Failed to open control connection to %d",
				   hapd->send_sock);
			return -1;
		}
	}

	return 0;
}

static void hostapd_cli_close_connection(struct hostapd_data *hapd)
{
	int ret;

	if (hapd_ctrl_conn == NULL)
		return;

	ret = wpa_ctrl_detach(hapd_ctrl_conn);
	if (ret < 0) {
		wpa_printf(MSG_INFO, "Failed to detach from wpa_supplicant: %s",
			   strerror(errno));
	}
	wpa_ctrl_close(hapd_ctrl_conn);
	hapd_ctrl_conn = NULL;
}

int zephyr_hostapd_ctrl_init(void *ctx)
{
	int ret;
	struct hostapd_data *hapd = ctx;

	hapd->send_sock = hapd->recv_sock = -1;

	ret = zvfs_eventfd(0, ZVFS_EFD_NONBLOCK);
	if (ret < 0) {
		ret = errno;
		wpa_printf(MSG_ERROR, "eventfd: %s (%d)", strerror(ret), ret);
		goto fail;
	}

	hapd->send_sock = ret;

	ret = zvfs_eventfd(0, ZVFS_EFD_NONBLOCK);
	if (ret < 0) {
		ret = errno;
		wpa_printf(MSG_ERROR, "eventfd: %s (%d)", strerror(ret), ret);
		goto fail;
	}

	hapd->recv_sock = ret;

	k_fifo_init(&hapd->send_fifo);
	k_fifo_init(&hapd->recv_fifo);

	wpa_printf(MSG_DEBUG, "hapd ctrl_iface: %d %d", hapd->send_sock,
		   hapd->recv_sock);
	wpa_printf(MSG_DEBUG, "hapd ctrl_iface: %p %p", &hapd->recv_fifo,
		   &hapd->send_fifo);

	eloop_register_read_sock(hapd->recv_sock, hostapd_ctrl_iface_receive,
				 hapd, NULL);

	ret = hostapd_cli_open_connection(hapd);
	if (ret < 0) {
		wpa_printf(MSG_INFO, "Failed to initialize control interface: %s: %d",
			   hapd->conf->iface, ret);
		goto fail;
	}

	return 0;

fail:
	if (hapd->send_sock >= 0)
		close(hapd->send_sock);
	if (hapd->recv_sock >= 0)
		close(hapd->recv_sock);

	return ret;
}

void zephyr_hostapd_ctrl_deinit(void *hapd)
{
	hostapd_cli_close_connection((struct hostapd_data *)hapd);
}

