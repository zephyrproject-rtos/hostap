/*
 * wpa_supplicant - Scan result fuzzer
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "wpa_supplicant_i.h"
#include "bss.h"
#include "../../../wpa_supplicant/config.h"
#include "../fuzzer-common.h"


struct arg_ctx {
	const u8 *data;
	size_t data_len;
	struct wpa_supplicant wpa_s;
	struct wpa_driver_ops driver;
	struct wpa_config conf;
};


static void process_scan_res(struct arg_ctx *ctx)
{
	struct os_reltime fetch_time;
	struct wpa_scan_res *res;

	wpa_hexdump(MSG_MSGDUMP, "fuzzer - scan-res", ctx->data, ctx->data_len);

	res = os_zalloc(sizeof(*res) + ctx->data_len);
	if (!res)
		return;
	os_memcpy(res + 1, ctx->data, ctx->data_len);
	res->ie_len = ctx->data_len;

	os_get_reltime(&fetch_time);

	wpa_bss_update_start(&ctx->wpa_s);
	wpa_bss_update_scan_res(&ctx->wpa_s, res, &fetch_time);
	wpa_bss_update_end(&ctx->wpa_s, NULL, 1);
	os_free(res);
}


static int init_wpa(struct arg_ctx *ctx)
{
	struct wpa_supplicant *wpa_s = &ctx->wpa_s;

	os_memcpy(wpa_s->bssid, "\x02\x00\x00\x00\x03\x00", ETH_ALEN);
	wpa_s->driver = &ctx->driver;
	wpa_s->conf = &ctx->conf;
	ctx->conf.bss_max_count = 100;
	if (wpa_bss_init(wpa_s) < 0)
		return -1;

	return 0;
}


static void deinit_wpa(struct arg_ctx *ctx)
{
	struct wpa_supplicant *wpa_s = &ctx->wpa_s;

	wpa_bss_flush(wpa_s);
	os_free(wpa_s->last_scan_res);
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct arg_ctx ctx;

	wpa_fuzzer_set_debug_level();

	if (os_program_init())
		return 0;

	os_memset(&ctx, 0, sizeof(ctx));
	ctx.data = data;
	ctx.data_len = size;
	if (init_wpa(&ctx))
		goto fail;

	process_scan_res(&ctx);

	deinit_wpa(&ctx);

fail:
	os_program_deinit();

	return 0;
}
