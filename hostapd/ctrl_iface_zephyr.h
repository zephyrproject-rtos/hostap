/*
 * Hostapd / Zephyr socket pair -based control interface
 * Copyright (c) 2022, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2024, NXP
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
#include "hostapd.h"
#include "ctrl_iface.h"
#include "common/wpa_ctrl.h"
#include "../wpa_supplicant/ctrl_iface_zephyr.h"

#define MAX_CTRL_MSG_LEN 1024

void hostapd_ctrl_iface_receive(int sock, void *eloop_ctx, void *sock_ctx);
