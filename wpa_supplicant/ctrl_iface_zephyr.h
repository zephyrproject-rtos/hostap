/*
 * WPA Supplicant / Zephyr socket pair -based control interface
 * Copyright (c) 2022, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
/* Per-interface ctrl_iface */
#include "utils/includes.h"

#include "utils/common.h"
#include "eloop.h"
#include "config.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "wpa_supplicant_i.h"
#include "ctrl_iface.h"
#include "common/wpa_ctrl.h"

#define MAX_CTRL_MSG_LEN 256
/**
 * struct wpa_ctrl_mon - Data structure of control interface monitors
 *
 * This structure is used to store information about registered control
 * interface monitors into struct wpa_supplicant.
 */
struct wpa_ctrl_mon {
	struct wpa_ctrl_mon *next;
	int sock;
	int debug_level;
	int errors;
};

struct ctrl_iface_priv {
	struct wpa_supplicant *wpa_s;
	/* 0 - wpa_cli, 1 - ctrl_iface */
	int sock_pair[2];
	int mon_sock_pair[2];
	struct wpa_ctrl_mon *ctrl_dst;
};

struct ctrl_iface_global_priv {
	struct wpa_global *global;
	/* 0 - wpa_cli, 1 - ctrl_iface */
	int sock_pair[2];
	int mon_sock_pair[2];
	struct wpa_ctrl_mon *ctrl_dst;
};

struct conn_msg {
	int msg_len;
	char msg[MAX_CTRL_MSG_LEN];
};
