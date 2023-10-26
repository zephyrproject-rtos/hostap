/*
 * WPA Supplicant / Zephyr socket pair -based control interface
 * Copyright (c) 2022, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "ctrl_iface_zephyr.h"

static void wpa_supplicant_ctrl_iface_receive(int sock, void *eloop_ctx,
					      void *sock_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	char *buf, *pos;
	int res;
	char *reply = NULL;
	size_t reply_len = 0;

	buf = os_zalloc(CTRL_IFACE_MAX_LEN + 1);
	if (!buf)
		return;
	res = recv(sock, buf, CTRL_IFACE_MAX_LEN, 0);
	if (res < 0) {
		wpa_printf(MSG_ERROR, "recvfrom(ctrl_iface): %s",
			   strerror(errno));
		os_free(buf);
		return;
	}

	if ((size_t) res > CTRL_IFACE_MAX_LEN) {
		wpa_printf(MSG_ERROR, "recvform(ctrl_iface): input truncated");
		os_free(buf);
		return;
	}
	buf[res] = '\0';

	pos = buf;
	while (*pos == ' ')
		pos++;

	reply = wpa_supplicant_ctrl_iface_process(wpa_s, pos,
							&reply_len);

	if (reply) {
		send(sock, reply, reply_len, 0);
		os_free(reply);
	} else if (reply_len == 1) {
		send(sock, "FAIL\n", 5, 0);
	} else if (reply_len == 2) {
		send(sock, "OK\n", 3, 0);
	}

	os_free(buf);
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

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, priv->sock_pair);
	if (ret != 0) {
		wpa_printf(MSG_ERROR, "socket(PF_INET): %s", strerror(errno));
		goto fail;
	}

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

	if (priv->sock_pair[0] > -1) {
		eloop_unregister_read_sock(priv->sock_pair[0]);
		close(priv->sock_pair[0]);
		priv->sock_pair[0] = -1;
	}

	if (priv->sock_pair[1] >= 0)
		close(priv->sock_pair[1]);

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
	char *buf, *pos;
	int res;
	char *reply = NULL;
	size_t reply_len = 0;

	buf = os_zalloc(CTRL_IFACE_MAX_LEN + 1);
	if (!buf)
		return;
	res = recv(sock, buf, CTRL_IFACE_MAX_LEN, 0);
	if (res < 0) {
		wpa_printf(MSG_ERROR, "recvfrom(ctrl_iface): %s",
			   strerror(errno));
		os_free(buf);
		return;
	}

	if ((size_t) res > CTRL_IFACE_MAX_LEN) {
		wpa_printf(MSG_ERROR, "recvform(ctrl_iface): input truncated");
		os_free(buf);
		return;
	}
	buf[res] = '\0';

	pos = buf;
	while (*pos == ' ')
		pos++;

	reply = wpa_supplicant_global_ctrl_iface_process(global, pos,
							&reply_len);

	if (reply) {
		send(sock, reply, reply_len, 0);
		os_free(reply);
	} else if (reply_len == 1) {
		send(sock, "FAIL\n", 5, 0);
	} else if (reply_len == 2) {
		send(sock, "OK\n", 3, 0);
	}

	os_free(buf);
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

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, priv->sock_pair);
	if (ret != 0) {
		wpa_printf(MSG_ERROR, "socket(PF_INET): %s", strerror(errno));
		goto fail;
	}

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

	if (priv->sock_pair[0] > -1) {
		eloop_unregister_read_sock(priv->sock_pair[0]);
		close(priv->sock_pair[0]);
		priv->sock_pair[0] = -1;
	}

	if (priv->sock_pair[1] >= 0)
		close(priv->sock_pair[1]);

	os_free(priv);
}
