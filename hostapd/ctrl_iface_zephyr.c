/*
 * Hostapd / Zephyr socket pair -based control interface
 * Copyright (c) 2022, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2024, NXP
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "ctrl_iface_zephyr.h"

void hostapd_ctrl_iface_receive(int sock, void *eloop_ctx,
					      void *sock_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	const char *pos;
	char *reply = NULL;
	int reply_len = 0;
	const int reply_size = MAX_CTRL_MSG_LEN / 2;
	zvfs_eventfd_t value;
	struct zephyr_msg *msg;

	do {
		zvfs_eventfd_read(sock, &value);

		msg = k_fifo_get(&hapd->recv_fifo, K_NO_WAIT);
		if (msg == NULL) {
			wpa_printf(MSG_ERROR, "fifo(ctrl_iface): %s",
				   "empty");
			return;
		}

		if (msg->data == NULL) {
			wpa_printf(MSG_ERROR, "fifo(global_ctrl_iface): %s",
				   "no data");
			goto out;
		}

		if (msg->len > 1 && msg->data[msg->len - 1] == '\n') {
			/* Remove the LF */
			msg->data[msg->len - 1] = '\0';
			msg->len--;
		}

		pos = msg->data;

		while (*pos == ' ') {
			pos++;
		}

		reply = os_malloc(reply_size);
		if (reply == NULL) {
			send_data(&hapd->send_fifo, hapd->send_sock, "FAIL\n", 5, 0);
			wpa_printf(MSG_ERROR, "hostapd cli malloc fail for reply buffer");
			goto out;
		}

		reply_len = hostapd_ctrl_iface_receive_process(hapd, (char *)pos, reply,
							       reply_size, NULL, 0);
		if (reply_len > 0) {
			send_data(&hapd->send_fifo, hapd->send_sock, reply, reply_len, 0);
		} else if (reply_len == 0) {
			send_data(&hapd->send_fifo, hapd->send_sock, "OK\n", 3, 0);
		} else if (reply_len < 0) {
			send_data(&hapd->send_fifo, hapd->send_sock, "FAIL\n", 5, 0);
		}

		os_free(reply);

	out:
		os_free(msg->data);
		os_free(msg);

	} while (!k_fifo_is_empty(&hapd->recv_fifo));
}
