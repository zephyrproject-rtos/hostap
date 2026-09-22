/*
 * WPA Supplicant / Zephyr socket pair -based control interface
 * Copyright (c) 2022, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <sys/socket.h>

#include "ctrl_iface_zephyr.h"

int send_data(struct k_fifo *fifo, int sock, const char *buf, size_t len, int flags)
{
	struct zephyr_msg *msg;

	msg = os_zalloc(sizeof(struct zephyr_msg));
	if (msg == NULL) {
		wpa_printf(MSG_ERROR, "malloc(ctrl_iface): %s",
			   "out of memory");
		return -ENOMEM;
	}

	msg->data = os_zalloc(len + 1); /* +1 for null-termination */
	if (msg->data == NULL) {
		wpa_printf(MSG_ERROR, "malloc(ctrl_iface): %s",
			   "out of memory");
		os_free(msg);
		return -ENOMEM;
	}

	memcpy(msg->data, buf, len);
	msg->len = len;

	k_fifo_put(fifo, msg);

	zvfs_eventfd_write(sock, 1);

	return 0;
}

static void wpa_supplicant_ctrl_iface_receive(int sock, void *eloop_ctx,
					      void *sock_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct ctrl_iface_priv *priv = sock_ctx;
	const char *pos;
	char *reply = NULL;
	size_t reply_len = 0;
	struct zephyr_msg *msg;
	zvfs_eventfd_t value;

	do {
		zvfs_eventfd_read(sock, &value);

		msg = k_fifo_get(&priv->recv_fifo, K_NO_WAIT);
		if (msg == NULL) {
			wpa_printf(MSG_ERROR, "fifo(ctrl_iface): %s",
				   "empty");
			return;
		}

		if (msg->data == NULL) {
			wpa_printf(MSG_ERROR, "fifo(ctrl_iface): %s",
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

		reply = wpa_supplicant_ctrl_iface_process(wpa_s, (char *)pos, &reply_len);
		if (reply) {
			send_data(&priv->send_fifo, priv->sock_pair[0], reply, reply_len, 0);
		} else if (reply_len == 1) {
			send_data(&priv->send_fifo, priv->sock_pair[0], "FAIL\n", 5, 0);
		} else if (reply_len == 2) {
			send_data(&priv->send_fifo, priv->sock_pair[0], "OK\n", 3, 0);
		}

out:
		os_free(msg->data);
		os_free(msg);

	} while (!k_fifo_is_empty(&priv->recv_fifo));
}


struct ctrl_iface_priv *
wpa_supplicant_ctrl_iface_init(struct wpa_supplicant *wpa_s)
{
	struct ctrl_iface_priv *priv;
	int ret;

	priv = os_zalloc(sizeof(*priv));
	if (priv == NULL)
		return NULL;
	priv->wpa_s = wpa_s;
	memset(priv->sock_pair, -1, sizeof(priv->sock_pair));

	if (wpa_s->conf->ctrl_interface == NULL)
		return priv;

	ret = zvfs_eventfd(0, ZVFS_EFD_NONBLOCK);
	if (ret < 0) {
		ret = errno;
		wpa_printf(MSG_ERROR, "eventfd: %s (%d)", strerror(ret), ret);
		goto fail;
	}

	priv->sock_pair[0] = ret;

	ret = zvfs_eventfd(0, ZVFS_EFD_NONBLOCK);
	if (ret < 0) {
		ret = errno;
		wpa_printf(MSG_ERROR, "eventfd: %s (%d)", strerror(ret), ret);
		goto fail;
	}

	priv->sock_pair[1] = ret;

	k_fifo_init(&priv->recv_fifo);
	k_fifo_init(&priv->send_fifo);

	wpa_printf(MSG_DEBUG, "ctrl_iface: %d %d", priv->sock_pair[0],
		   priv->sock_pair[1]);
	wpa_printf(MSG_DEBUG, "ctrl_iface: %p %p", &priv->recv_fifo,
		   &priv->send_fifo);

	os_free(wpa_s->conf->ctrl_interface);
	wpa_s->conf->ctrl_interface = os_strdup("zephyr:");
	if (!wpa_s->conf->ctrl_interface) {
		wpa_msg(wpa_s, MSG_ERROR, "Failed to malloc ctrl_interface");
		goto fail;
	}

	eloop_register_read_sock(priv->sock_pair[1], wpa_supplicant_ctrl_iface_receive,
				 wpa_s, priv);

	return priv;

fail:
	if (priv->sock_pair[0] >= 0)
		close(priv->sock_pair[0]);
	if (priv->sock_pair[1] >= 0)
		close(priv->sock_pair[1]);
	os_free(priv);
	return NULL;
}


void wpa_supplicant_ctrl_iface_deinit(struct wpa_supplicant *wpa_s,
				      struct ctrl_iface_priv *priv)
{
	if (!priv)
		return;

	if (priv->sock_pair[1] > -1) {
		eloop_unregister_read_sock(priv->sock_pair[1]);
		close(priv->sock_pair[1]);
		priv->sock_pair[1] = -1;
	}

	if (priv->sock_pair[0] >= 0) {
               close(priv->sock_pair[0]);
               priv->sock_pair[0] = -1;
	}

	os_free(priv);
}

void
wpa_supplicant_ctrl_iface_wait(struct ctrl_iface_priv *priv)
{
}

/* Global control interface */

static void wpa_supplicant_global_ctrl_iface_receive(int sock, void *eloop_ctx,
						     void *sock_ctx)
{
	struct wpa_global *global = eloop_ctx;
	struct ctrl_iface_global_priv *priv = sock_ctx;
	const char *pos;
	char *reply = NULL;
	size_t reply_len = 0;
	struct zephyr_msg *msg;
	zvfs_eventfd_t value;

	do {
		zvfs_eventfd_read(sock, &value);

		msg = k_fifo_get(&priv->fifo_recv, K_NO_WAIT);
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

		reply = wpa_supplicant_global_ctrl_iface_process(global, (char *)pos,
								 &reply_len);
		if (reply) {
			send_data(&priv->fifo_send, priv->sock_pair[0], reply, reply_len, 0);
		} else if (reply_len == 1) {
			send_data(&priv->fifo_send, priv->sock_pair[0], "FAIL\n", 5, 0);
		} else if (reply_len == 2) {
			send_data(&priv->fifo_send, priv->sock_pair[0], "OK\n", 3, 0);
		}

out:
		os_free(msg->data);
		os_free(msg);

	} while (!k_fifo_is_empty(&priv->fifo_recv));
}

struct ctrl_iface_global_priv *
wpa_supplicant_global_ctrl_iface_init(struct wpa_global *global)
{
	struct ctrl_iface_global_priv *priv;
	int ret;

	priv = os_zalloc(sizeof(*priv));
	if (priv == NULL)
		return NULL;
	priv->global = global;
	memset(priv->sock_pair, -1, sizeof(priv->sock_pair));

	ret = zvfs_eventfd(0, ZVFS_EFD_NONBLOCK);
	if (ret < 0) {
		ret = errno;
		wpa_printf(MSG_ERROR, "eventfd: %s (%d)", strerror(ret), ret);
		goto fail;
	}

	priv->sock_pair[0] = ret;

	ret = zvfs_eventfd(0, ZVFS_EFD_NONBLOCK);
	if (ret < 0) {
		ret = errno;
		wpa_printf(MSG_ERROR, "eventfd: %s (%d)", strerror(ret), ret);
		goto fail;
	}

	priv->sock_pair[1] = ret;

	k_fifo_init(&priv->fifo_recv);
	k_fifo_init(&priv->fifo_send);

	wpa_printf(MSG_DEBUG, "ctrl_iface_global: %d %d", priv->sock_pair[0],
		   priv->sock_pair[1]);
	wpa_printf(MSG_DEBUG, "ctrl_iface_global: %p %p", &priv->fifo_recv,
		   &priv->fifo_send);

	os_free(global->params.ctrl_interface);
	global->params.ctrl_interface = os_strdup("g_zephyr:");
	if (!global->params.ctrl_interface) {
		wpa_printf(MSG_ERROR, "Failed to malloc global ctrl_interface\n");
		goto fail;
	}

	eloop_register_read_sock(priv->sock_pair[1], wpa_supplicant_global_ctrl_iface_receive,
				 global, priv);

	return priv;

fail:
	if (priv->sock_pair[0] >= 0)
		close(priv->sock_pair[0]);
	if (priv->sock_pair[1] >= 0)
		close(priv->sock_pair[1]);
	os_free(priv);
	return NULL;
}

void
wpa_supplicant_global_ctrl_iface_deinit(struct ctrl_iface_global_priv *priv)
{
	if (!priv)
		return;

	if (priv->sock_pair[1] > -1) {
		eloop_unregister_read_sock(priv->sock_pair[1]);
		close(priv->sock_pair[1]);
		priv->sock_pair[1] = -1;
	}

	if (priv->sock_pair[0] >= 0) {
		close(priv->sock_pair[0]);
		priv->sock_pair[0] = -1;
	}

	os_free(priv);
}
