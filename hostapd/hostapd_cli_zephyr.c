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
#include "hapd_events.h"
#include "ctrl_iface_zephyr.h"
#include "hostapd_cli_zephyr.h"

#define CMD_BUF_LEN  1024
#define MAX_CMD_SIZE 512
#define MAX_ARGS 32

int hapd_sockpair[2];
int hapd_mon_sockpair[2];
struct wpa_ctrl *hapd_ctrl_conn = NULL;
struct wpa_ctrl *hapd_mon_conn = NULL;

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

static void hostapd_cli_recv_pending(struct wpa_ctrl *ctrl, struct hostapd_data *hapd)
{
	while (wpa_ctrl_pending(ctrl) > 0) {
		char buf[sizeof(struct conn_msg)];
		size_t hlen = sizeof(int);
		size_t plen = MAX_CTRL_MSG_LEN;

		if (wpa_ctrl_recv(ctrl, buf, &hlen) == 0 &&
		    hlen == sizeof(int)) {
			plen = *((int *)buf);
		} else {
			wpa_printf(MSG_ERROR, "Could not read pending message header len %d.\n", hlen);
			continue;
		}

		if (wpa_ctrl_recv(ctrl, buf + sizeof(int), &plen) == 0) {
			struct conn_msg *msg = (struct conn_msg *)buf;

			msg->msg[msg->msg_len] = '\0';
			wpa_printf(MSG_DEBUG, "Received len: %d, msg_len:%d - %s->END\n",
				   plen, msg->msg_len, msg->msg);
			if (msg->msg_len >= MAX_CTRL_MSG_LEN) {
				wpa_printf(MSG_DEBUG, "Too long message received.\n");
				continue;
			}

			if (msg->msg_len > 0) {
#ifdef CONFIG_WIFI_NM_WPA_SUPPLICANT_DPP
				if (strncmp(msg->msg, "DPP", 3) == 0) {
					hostapd_handle_dpp_event(hapd, msg->msg, msg->msg_len);
				}
#endif /* CONFIG_WIFI_NM_WPA_SUPPLICANT_DPP */
			}
		} else {
			wpa_printf(MSG_INFO, "Could not read pending message.\n");
		}
	}
}

static void hostapd_cli_mon_receive(int sock, void *eloop_ctx,
				    void *sock_ctx)
{
	struct hostapd_data *hapd = (struct hostapd_data *)eloop_ctx;

	hostapd_cli_recv_pending(hapd_mon_conn, hapd);
}

static int hostapd_cli_open_connection(struct hostapd_data *hapd)
{
	int ret;

	if (!hapd_ctrl_conn) {
		hapd_ctrl_conn = wpa_ctrl_open(hapd_sockpair[0]);
		if (hapd_ctrl_conn == NULL) {
			wpa_printf(MSG_ERROR, "Failed to open control connection to %d",
				   hapd_sockpair[0]);
			return -1;
		}
	}

	if (!hapd_mon_conn) {
		ret = socketpair(AF_UNIX, SOCK_STREAM, 0, hapd_mon_sockpair);
		if (ret != 0) {
			wpa_printf(MSG_ERROR, "Failed to open monitor connection: %s",
				   strerror(errno));
			goto fail;
		}

		hapd_mon_conn = wpa_ctrl_open(hapd_mon_sockpair[0]);
		if (hapd_mon_conn) {
			eloop_register_read_sock(hapd_mon_sockpair[0],
						 hostapd_cli_mon_receive, hapd, NULL);
		}
	}

	return 0;
fail:
	wpa_ctrl_close(hapd_ctrl_conn);
	return -1;
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

	eloop_unregister_read_sock(hapd_mon_sockpair[0]);
	wpa_ctrl_close(hapd_mon_conn);
	hapd_mon_conn = NULL;

	close(hapd_mon_sockpair[1]);
	hapd_mon_sockpair[1] = -1;
}

void hostapd_msg_send(void *hapd, int level,
		      enum wpa_msg_type type,
		      const char *buf, size_t len)
{
	struct conn_msg msg;

	if (len > MAX_CTRL_MSG_LEN)
	{
		wpa_printf(MSG_ERROR, "CTRL_MSG too long");
		return;
	}

	if (type == WPA_MSG_PER_INTERFACE && level >= MSG_INFO &&
	    hapd_mon_sockpair[1] > 0) {
		memcpy(&msg.msg, buf, len);
		msg.msg_len = len;
		if (send(hapd_mon_sockpair[1], &msg, len + 4, 0) < 0) {
			wpa_printf(MSG_ERROR,
				   "sendto(hostapd monitor sock): %s",
				   strerror(errno));
		}
	}
}

int zephyr_hostapd_ctrl_init(void *ctx)
{
	int ret;
	struct hostapd_data *hapd = ctx;

	memset(hapd_sockpair, -1, sizeof(hapd_sockpair));
	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, hapd_sockpair);
	if (ret != 0) {
		wpa_printf(MSG_ERROR, "socket(PF_INET): %s", strerror(errno));
		goto fail;
	}

	eloop_register_read_sock(hapd_sockpair[1], hostapd_ctrl_iface_receive,
				 hapd, NULL);

	ret = hostapd_cli_open_connection(hapd);
	if (ret < 0) {
		wpa_printf(MSG_INFO, "Failed to initialize control interface: %s: %d", hapd->conf->iface, ret);
		return ret;
	}

fail:
	return ret;
}

void zephyr_hostapd_ctrl_deinit(void *hapd)
{
	hostapd_cli_close_connection((struct hostapd_data *)hapd);
}

