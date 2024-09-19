/*
 * WPA Supplicant - command line interface for wpa_supplicant daemon
 *                  for Zephyr (based on wpa_cli.c)
 * Copyright (c) 2004-2022, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "includes.h"

#include "common/cli.h"
#include "common/wpa_ctrl.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/edit.h"
#include "utils/list.h"
#include "wpa_supplicant_i.h"
#include "ctrl_iface.h"
#include "common/version.h"
#include "common/ieee802_11_defs.h"

#include "supp_main.h"
#include "supp_events.h"
#include "wpa_cli_zephyr.h"
#include "ctrl_iface_zephyr.h"

#define CMD_BUF_LEN  1024
#define MAX_CMD_SIZE 512
#define MAX_RESPONSE_SIZE 512
#define DEFAULT_IFNAME "wlan0"
#define MAX_ARGS 32

struct wpa_ctrl *ctrl_conn;
struct wpa_ctrl *mon_conn;
struct wpa_ctrl *global_ctrl_conn;
char *ifname_prefix = NULL;
extern struct wpa_global *global;

static void wpa_cli_msg_cb(char *msg, size_t len)
{
	wpa_printf(MSG_INFO, "%s", msg);
}

static int _wpa_ctrl_command(struct wpa_ctrl *ctrl, const char *cmd, int print, char *resp)
{
	char buf[CMD_BUF_LEN] = { 0 };
	size_t len;
	int ret;

	if (ctrl_conn == NULL && global_ctrl_conn == NULL) {
		wpa_printf(MSG_ERROR, "Not connected to wpa_supplicant - command dropped.");
		return -1;
	}

	if (ifname_prefix) {
		os_snprintf(buf, sizeof(buf), "IFNAME=%s %s", ifname_prefix, cmd);
		buf[sizeof(buf) - 1] = '\0';
		cmd = buf;
	}

	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, cmd, os_strlen(cmd), buf, &len, wpa_cli_msg_cb);
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

static int wpa_ctrl_command_resp(struct wpa_ctrl *ctrl, const char *cmd, char *resp)
{
	return _wpa_ctrl_command(ctrl, cmd, 0, resp);
}

int zephyr_wpa_cli_cmd_resp(const char *cmd, char *resp)
{
	return _wpa_ctrl_command(ctrl_conn, cmd, 1, resp);
}

static void wpa_cli_close_connection(struct wpa_supplicant *wpa_s)
{
	int ret;

	if (ctrl_conn == NULL)
		return;

	ret = wpa_ctrl_detach(ctrl_conn);
	if (ret < 0) {
		wpa_printf(MSG_INFO, "Failed to detach from wpa_supplicant: %s",
			strerror(errno));
	}
	wpa_ctrl_close(ctrl_conn);
	ctrl_conn = NULL;

	eloop_unregister_read_sock(wpa_s->ctrl_iface->mon_sock_pair[0]);

	wpa_ctrl_close(mon_conn);
	mon_conn = NULL;

	close(wpa_s->ctrl_iface->mon_sock_pair[1]);
	wpa_s->ctrl_iface->mon_sock_pair[1] = -1;
}

static void wpa_cli_recv_pending(struct wpa_ctrl *ctrl, struct wpa_supplicant *wpa_s)
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
				/* Only interested in CTRL-EVENTs */
				if (strncmp(msg->msg, "CTRL-EVENT", 10) == 0) {
					if (strncmp(msg->msg, "CTRL-EVENT-SIGNAL-CHANGE", 24) == 0) {
						supplicant_send_wifi_mgmt_event(wpa_s->ifname,
									NET_EVENT_WIFI_CMD_SIGNAL_CHANGE,
									msg->msg, msg->msg_len);
					} else {
						supplicant_send_wifi_mgmt_event(wpa_s->ifname,
									NET_EVENT_WIFI_CMD_SUPPLICANT,
									msg->msg, msg->msg_len);
					}
				} else if (strncmp(msg->msg, "RRM-NEIGHBOR-REP-RECEIVED", 25) == 0) {
						supplicant_send_wifi_mgmt_event(wpa_s->ifname,
									NET_EVENT_WIFI_CMD_NEIGHBOR_REP_RECEIVED,
									msg->msg, msg->msg_len);
				}
			}
		} else {
			wpa_printf(MSG_INFO, "Could not read pending message.\n");
		}
	}
}

static void wpa_cli_mon_receive(int sock, void *eloop_ctx,
					      void *sock_ctx)
{
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *)eloop_ctx;

	wpa_cli_recv_pending(mon_conn, wpa_s);
}

static int wpa_cli_open_connection(struct wpa_supplicant *wpa_s)
{
	int ret;

	ctrl_conn = wpa_ctrl_open(wpa_s->ctrl_iface->sock_pair[0]);
	if (ctrl_conn == NULL) {
		wpa_printf(MSG_ERROR, "Failed to open control connection to %d",
			wpa_s->ctrl_iface->sock_pair[0]);
		return -1;
	}

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, wpa_s->ctrl_iface->mon_sock_pair);
	if (ret != 0) {
		wpa_printf(MSG_ERROR, "Failed to open monitor connection: %s",
			    strerror(errno));
		goto fail;
	}
	mon_conn = wpa_ctrl_open(wpa_s->ctrl_iface->mon_sock_pair[0]);
	if (mon_conn) {
		if (wpa_ctrl_attach(ctrl_conn) == 0) {
			eloop_register_read_sock(wpa_s->ctrl_iface->mon_sock_pair[0],
						wpa_cli_mon_receive, wpa_s, NULL);
		}
	}

	return 0;
fail:
	wpa_ctrl_close(ctrl_conn);
	return -1;
}

static int wpa_cli_open_global_ctrl(void)
{
	global_ctrl_conn = wpa_ctrl_open(zephyr_get_default_supplicant_context()->
					 ctrl_iface->sock_pair[0]);
	if (global_ctrl_conn == NULL) {
		wpa_printf(MSG_ERROR, "Failed to open global control connection to "
			   "%d - %s",
			   zephyr_get_default_supplicant_context()->ctrl_iface->sock_pair[0],
			   strerror(errno));
		return -1;
	}

	return 0;
}

static void wpa_cli_close_global_ctrl(void)
{
	if (global_ctrl_conn == NULL)
		return;

	wpa_ctrl_close(global_ctrl_conn);
	global_ctrl_conn = NULL;
}


/* Lifted from zephyr shell_utils.c to handle escapes */
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


char supp_make_argv(size_t *argc, const char **argv, char *cmd,
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

int wpa_ctrl_command(struct wpa_ctrl *ctrl, const char *cmd)
{
	return _wpa_ctrl_command(ctrl, cmd, 0, NULL);
}

int wpa_ctrl_command_interactive(struct wpa_ctrl *ctrl, const char *cmd)
{
	return _wpa_ctrl_command(ctrl, cmd, 1, NULL);
}

/* Public APIs */

int zephyr_global_wpa_ctrl_init(void)
{
	int ret;

	ret = wpa_cli_open_global_ctrl();
	if (ret < 0) {
		wpa_printf(MSG_INFO, "Failed to initialize global control interface: %d", ret);
		return ret;
	}

	return ret;
}


void zephyr_global_wpa_ctrl_deinit(void)
{
	return wpa_cli_close_global_ctrl();
}

int zephyr_wpa_ctrl_init(void *wpa_s)
{
	int ret;
	struct wpa_supplicant *supp = wpa_s;

	ret = wpa_cli_open_connection(supp);
	if (ret < 0) {
		wpa_printf(MSG_INFO, "Failed to initialize control interface: %s: %d", supp->ifname, ret);
		return ret;
	}

	return ret;
}

void zephyr_wpa_ctrl_deinit(void *wpa_s)
{
	wpa_cli_close_connection((struct wpa_supplicant *)wpa_s);
}

int zephyr_wpa_ctrl_zephyr_cmd(int argc, const char *argv[])
{
	return wpa_request(ctrl_conn, argc , (char **) argv);
}

int zephyr_wpa_cli_cmd_v(const char *fmt, ...)
{
	va_list cmd_args;
	int argc;
	const char *argv[MAX_ARGS];
	char cmd[MAX_CMD_SIZE];

	va_start(cmd_args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, cmd_args);
	va_end(cmd_args);

	(void)supp_make_argv(&argc, &argv[0], cmd, MAX_ARGS);

	wpa_printf(MSG_DEBUG, "Calling wpa_cli: %s, argc: %d", cmd, argc);
	for (int i = 0; i < argc; i++)
		wpa_printf(MSG_DEBUG, "argv[%d]: %s", i, argv[i]);

	return zephyr_wpa_ctrl_zephyr_cmd(argc, argv);
}

int z_wpa_ctrl_add_network(struct add_network_resp *resp)
{
	int ret;
	char buf[MAX_RESPONSE_SIZE] = {0};

	ret =  wpa_ctrl_command_resp(ctrl_conn, "ADD_NETWORK", buf);
	if (ret) {
		return ret;
	}

	ret = sscanf((const char *)buf, "%d", &resp->network_id);
	if (ret < 0) {
		wpa_printf(MSG_INFO, "Failed to parse ADD_NETWORK response: %s",
			strerror(errno));
		return -1;
	}

	return 0;
}

int z_wpa_ctrl_signal_poll(struct signal_poll_resp *resp)
{
	int ret;
	char buf[MAX_RESPONSE_SIZE] = {0};

	ret = wpa_ctrl_command_resp(ctrl_conn, "SIGNAL_POLL", buf);
	if (ret) {
		return ret;
	}

	ret = sscanf((const char *)buf, "RSSI=%d", &resp->rssi);
	if (ret < 0) {
		wpa_printf(MSG_INFO, "Failed to parse SIGNAL_POLL response: %s",
			strerror(errno));
		return -1;
	}

	return 0;
}

int z_wpa_ctrl_status(struct status_resp *resp)
{
	int ret;
	char buf[MAX_RESPONSE_SIZE] = {0};

	ret = wpa_ctrl_command_resp(ctrl_conn, "STATUS", buf);
	if (ret) {
		return ret;
	}

	ret = sscanf((const char *)buf, "bssid=%%*\nfreq=%%*\nssid=%s", resp->ssid);
	if (ret < 0) {
		wpa_printf(MSG_INFO, "Failed to parse STATUS response: %s",
			strerror(errno));
		return -1;
	}
	resp->ssid_len = strlen(resp->ssid);

	return 0;
}

int zephyr_wpa_global_ctrl_zephyr_cmd(int argc, const char *argv[])
{
	return wpa_request(global_ctrl_conn, argc , (char **) argv);
}

int zephyr_wpa_cli_global_cmd_v(const char *fmt, ...)
{
	va_list cmd_args;
	int argc;
	const char *argv[MAX_ARGS] = {0};
	char cmd[MAX_CMD_SIZE];

	va_start(cmd_args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, cmd_args);
	va_end(cmd_args);

	(void)supp_make_argv(&argc, &argv[0], cmd, MAX_ARGS);

	wpa_printf(MSG_DEBUG, "Calling wpa_cli: %s, argc: %d", cmd, argc);
	for (int i = 0; i < argc; i++)
		wpa_printf(MSG_DEBUG, "argv[%d]: %s", i, argv[i]);

	return zephyr_wpa_global_ctrl_zephyr_cmd(argc, argv);
}
