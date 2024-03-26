/*
 * WPA Supplicant / Zephyr socket pair -based control interface
 * Copyright (c) 2022, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "ctrl_iface_zephyr.h"


static int wpa_supplicant_ctrl_mon_iface_attach(struct wpa_ctrl_mon **head, int sock)
{
	struct wpa_ctrl_mon *dst;

	dst = os_zalloc(sizeof(*dst));
	if (dst == NULL)
		return -1;

	dst->sock = sock;
	dst->debug_level = MSG_INFO;
	dst->next = *head;
	*head = dst;
	return 0;
}


static int wpa_supplicant_ctrl_mon_iface_detach(struct wpa_ctrl_mon **head, int sock)
{
	struct wpa_ctrl_mon *dst, *prev = NULL;

	dst = *head;
	while (dst) {
		if (dst->sock == sock) {
			if (prev == NULL) {
				*head = dst->next;
			} else {
				prev->next = dst->next;
			}
			os_free(dst);
			return 0;
		}
		prev = dst;
		dst = dst->next;
	}
	return -1;
}

static void wpa_supplicant_ctrl_iface_send(struct wpa_supplicant *wpa_s,
					   const char *ifname, int sock,
					   struct wpa_ctrl_mon **head,
					   int level, const char *buf,
					   size_t len)
{
	struct wpa_ctrl_mon *dst, *next;
	char levelstr[64];
	int idx;
	struct conn_msg msg;

	dst = *head;
	if (sock < 0 || dst == NULL)
		return;

	if (ifname)
		os_snprintf(levelstr, sizeof(levelstr), "IFNAME=%s <%d>",
			    ifname, level);
	else
		os_snprintf(levelstr, sizeof(levelstr), "<%d>", level);

	idx = 0;
	while (dst) {
		next = dst->next;
		if (level >= dst->debug_level) {
			memcpy(&msg.msg, buf, len);
			msg.msg_len = len;
			if (send(dst->sock, &msg, sizeof(msg), 0) < 0) {
				wpa_printf(MSG_ERROR,
					   "sendto(CTRL_IFACE monitor): %s",
					   strerror(errno));
				dst->errors++;
			} else {
				dst->errors = 0;
			}
		}
		idx++;
		dst = next;
	}
}

static void wpa_supplicant_ctrl_iface_msg_cb(void *ctx, int level,
					     enum wpa_msg_type type,
					     const char *txt, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;

	if (!wpa_s)
		return;

	if (type != WPA_MSG_NO_GLOBAL && wpa_s->global->ctrl_iface) {
		struct ctrl_iface_global_priv *priv = wpa_s->global->ctrl_iface;

		if (priv->ctrl_dst) {
			wpa_supplicant_ctrl_iface_send(wpa_s, type != WPA_MSG_PER_INTERFACE ?
							NULL : wpa_s->ifname,
							priv->sock_pair[0],
							 &priv->ctrl_dst, level, txt, len);
		}
	}

	if (type == WPA_MSG_ONLY_GLOBAL || !wpa_s->ctrl_iface)
		return;

	wpa_supplicant_ctrl_iface_send(wpa_s, NULL, wpa_s->ctrl_iface->sock_pair[0],
				       &wpa_s->ctrl_iface->ctrl_dst,
				       level, txt, len);
}


static void wpa_supplicant_ctrl_iface_receive(int sock, void *eloop_ctx,
					      void *sock_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	char buf[CTRL_IFACE_MAX_LEN + 1];
	char *pos;
	int res;
	char *reply = NULL;
	size_t reply_len = 0;

	res = recv(sock, buf, CTRL_IFACE_MAX_LEN, 0);
	if (res < 0) {
		wpa_printf(MSG_ERROR, "recvfrom(ctrl_iface): %s",
			   strerror(errno));
		return;
	}

	if (!res) {
		eloop_unregister_sock(sock, EVENT_TYPE_READ);
		wpa_printf(MSG_DEBUG, "ctrl_iface: Peer unexpectedly shut down "
			   "socket");
		return;
	}

	if ((size_t) res > CTRL_IFACE_MAX_LEN) {
		wpa_printf(MSG_ERROR, "recvform(ctrl_iface): input truncated");
		return;
	}
	buf[res] = '\0';

	pos = buf;
	while (*pos == ' ')
		pos++;

	if (os_strcmp(pos, "ATTACH") == 0) {
		if (wpa_supplicant_ctrl_mon_iface_attach(&wpa_s->ctrl_iface->ctrl_dst,
						    wpa_s->ctrl_iface->mon_sock_pair[1])){
			reply_len = 1;
		}
		else {
			reply_len = 2;
		}
	} else if (os_strcmp(pos, "DETACH") == 0) {
		if (wpa_supplicant_ctrl_mon_iface_detach(&wpa_s->ctrl_iface->ctrl_dst,
						    wpa_s->ctrl_iface->mon_sock_pair[1])) {
			reply_len = 1;
		}
		else {
			reply_len = 2;
		}
	} else {
		reply = wpa_supplicant_ctrl_iface_process(wpa_s, pos,
							&reply_len);
	}

	if (reply) {
		send(sock, reply, reply_len, 0);
	} else if (reply_len == 1) {
		send(sock, "FAIL\n", 5, 0);
	} else if (reply_len == 2) {
		send(sock, "OK\n", 3, 0);
	}
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

	wpa_msg_register_cb(wpa_supplicant_ctrl_iface_msg_cb);

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
	char buf[CTRL_IFACE_MAX_LEN + 1];
	char *pos;
	int res;
	char *reply = NULL;
	size_t reply_len = 0;

	res = recv(sock, buf, CTRL_IFACE_MAX_LEN, 0);
	if (res < 0) {
		wpa_printf(MSG_ERROR, "recvfrom(g_ctrl_iface): %s",
			   strerror(errno));
		return;
	}

	if (!res) {
		eloop_unregister_sock(sock, EVENT_TYPE_READ);
		wpa_printf(MSG_DEBUG, "g_ctrl_iface: Peer unexpectedly shut down "
			   "socket");
		return;
	}

	if ((size_t) res > CTRL_IFACE_MAX_LEN) {
		wpa_printf(MSG_ERROR, "recvform(g_ctrl_iface): input truncated");
		return;
	}
	buf[res] = '\0';

	pos = buf;
	while (*pos == ' ')
		pos++;

	if (os_strcmp(pos, "ATTACH") == 0) {
		if (wpa_supplicant_ctrl_mon_iface_attach(&global->ctrl_iface->ctrl_dst,
						    global->ctrl_iface->mon_sock_pair[1])) {
			reply_len = 1;
		}
		else {
			reply_len = 2;
		}
	} else if (os_strcmp(pos, "DETACH") == 0) {
		if (wpa_supplicant_ctrl_mon_iface_detach(&global->ctrl_iface->ctrl_dst,
						    global->ctrl_iface->mon_sock_pair[1])) {
			reply_len = 1;
		}
		else {
			reply_len = 2;
		}
	} else {
	reply = wpa_supplicant_global_ctrl_iface_process(global, pos,
							&reply_len);
	}

	if (reply) {
		send(sock, reply, reply_len, 0);
	} else if (reply_len == 1) {
		send(sock, "FAIL\n", 5, 0);
	} else if (reply_len == 2) {
		send(sock, "OK\n", 3, 0);
	}
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

	if (priv->sock_pair[1] > -1) {
		eloop_unregister_read_sock(priv->sock_pair[1]);
		close(priv->sock_pair[1]);
		priv->sock_pair[1] = -1;
	}

	if (priv->sock_pair[0] >= 0)
		close(priv->sock_pair[0]);

	os_free(priv);
}
