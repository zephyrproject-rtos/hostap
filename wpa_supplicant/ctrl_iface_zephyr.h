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

#include <zephyr/zvfs/eventfd.h>

struct zephyr_msg {
	/**
	 * The fifo is used by RX/TX threads and by socket layer. The net_pkt
	 * is queued via fifo to the processing thread.
	 */
	intptr_t fifo;

	/**
	 * Dynamic data to send. The receiver is responsible for freeing the data.
	 */
	char *data;

	/**
	 * Length of the data.
	 */
	size_t len;
};

struct ctrl_iface_priv {
	struct wpa_supplicant *wpa_s;
	int sock_pair[2];
	struct k_fifo recv_fifo;
	struct k_fifo send_fifo;
};

struct ctrl_iface_global_priv {
	struct wpa_global *global;
	int sock_pair[2];
	struct k_fifo fifo_recv;
	struct k_fifo fifo_send;
};

extern int send_data(struct k_fifo *fifo, int sock,
		     const char *buf, size_t len, int flags);
extern int send_data_const(struct k_fifo *fifo, int sock,
			   const char *buf, size_t len);
