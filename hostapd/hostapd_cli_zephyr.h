/*
 * Copyright (c) 2004-2022, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2024, NXP
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef __HOSTAPD_CLI_ZEPHYR_H_
#define __HOSTAPD_CLI_ZEPHYR_H_

#include <zephyr/kernel.h>

#include "common/wpa_ctrl.h"

void hostapd_cli_msg_cb(char *msg, size_t len);
int hostapd_request(struct wpa_ctrl *ctrl, int argc, char *argv[]);
int hostapd_ctrl_command(struct wpa_ctrl *ctrl, const char *cmd);
int hostapd_ctrl_command_interactive(struct wpa_ctrl *ctrl, const char *cmd);
int zephyr_hostapd_cli_cmd_resp(struct wpa_ctrl *ctrl, const char *cmd, char *resp);
int zephyr_hostapd_cli_cmd_v(struct wpa_ctrl *ctrl, const char *fmt, ...);
int zephyr_hostapd_ctrl_init(void *ctx);
int zephyr_hostapd_ctrl_zephyr_cmd(struct wpa_ctrl *ctrl, int argc, const char *argv[]);
#endif /* __HOSTAPD_CLI_ZEPHYR_H_ */
