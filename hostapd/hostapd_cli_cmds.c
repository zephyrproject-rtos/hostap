/*
 * hostapd - command line interface for hostapd daemon
 * Copyright (c) 2004-2022, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common/wpa_ctrl.h"
#include "common/ieee802_11_defs.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/edit.h"
#include "common/version.h"
#include "common/cli.h"
#include "hostapd_cli_zephyr.h"

static DEFINE_DL_LIST(stations); /* struct cli_txt_entry */

#define CMD_BUF_LEN 1024

static int hostapd_cli_cmd(struct wpa_ctrl *ctrl, const char *cmd,
			   int min_args, int argc, char *argv[])
{
	char buf[CMD_BUF_LEN] = {0};
	int ret = 0;
	bool interactive = 0;

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "interactive") == 0) {
			interactive = 1;
			argv[i] = NULL;
			argc--;
			break;
		}
	}

	if (argc < min_args) {
		wpa_printf(MSG_INFO, "Invalid %s command - at least %d argument%s "
		       "required.\n", cmd, min_args,
		       min_args > 1 ? "s are" : " is");
		return -1;
	}

	if (write_cmd(buf, CMD_BUF_LEN, cmd, argc, argv) < 0){
		ret = -1;
		goto out;
	}

	if (interactive)
		ret = hostapd_ctrl_command_interactive(ctrl, buf);
	else
		ret = hostapd_ctrl_command(ctrl, buf);

out:
	return ret;

}

static int hostapd_cli_cmd_set(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc == 1) {
		res = os_snprintf(cmd, sizeof(cmd), "SET %s ", argv[0]);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wpa_printf(MSG_INFO, "Too long SET command.\n");
			return -1;
		}
		return hostapd_cli_cmd(ctrl, cmd, 0, argc, argv);
	}

	return hostapd_cli_cmd(ctrl, "SET", 2, argc, argv);
}


static char ** hostapd_complete_set(const char *str, int pos)
{
        int arg = get_cmd_arg_num(str, pos);
        const char *fields[] = {
#ifdef CONFIG_WPS_TESTING
                "wps_version_number", "wps_testing_stub_cred",
                "wps_corrupt_pkhash",
#endif /* CONFIG_WPS_TESTING */
#ifdef CONFIG_INTERWORKING
                "gas_frag_limit",
#endif /* CONFIG_INTERWORKING */
#ifdef CONFIG_TESTING_OPTIONS
                "ext_mgmt_frame_handling", "ext_eapol_frame_io",
#endif /* CONFIG_TESTING_OPTIONS */
#ifdef CONFIG_MBO
                "mbo_assoc_disallow",
#endif /* CONFIG_MBO */
                "deny_mac_file", "accept_mac_file",
        };
        int i, num_fields = ARRAY_SIZE(fields);

        if (arg == 1) {
                char **res;

                res = os_calloc(num_fields + 1, sizeof(char *));
                if (!res)
                        return NULL;
                for (i = 0; i < num_fields; i++) {
                        res[i] = os_strdup(fields[i]);
                        if (!res[i])
                                return res;
                }
                return res;
        }
        return NULL;
}


static int hostapd_cli_cmd_disassociate(struct wpa_ctrl *ctrl, int argc,
                                        char *argv[])
{
        char buf[64];
        if (argc < 1) {
                printf("Invalid 'disassociate' command - exactly one "
                       "argument, STA address, is required.\n");
                return -1;
        }
        if (argc > 1)
                os_snprintf(buf, sizeof(buf), "DISASSOCIATE %s %s",
                            argv[0], argv[1]);
        else
                os_snprintf(buf, sizeof(buf), "DISASSOCIATE %s", argv[0]);
        return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_deauthenticate(struct wpa_ctrl *ctrl, int argc,
                                          char *argv[])
{
        char buf[64];
        if (argc < 1) {
                printf("Invalid 'deauthenticate' command - exactly one "
                       "argument, STA address, is required.\n");
                return -1;
        }
        if (argc > 1)
                os_snprintf(buf, sizeof(buf), "DEAUTHENTICATE %s %s",
                            argv[0], argv[1]);
        else
                os_snprintf(buf, sizeof(buf), "DEAUTHENTICATE %s", argv[0]);
        return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_status(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	if (argc > 0 && os_strcmp(argv[0], "driver") == 0)
		return hostapd_ctrl_command(ctrl, "STATUS-DRIVER");
	return hostapd_ctrl_command(ctrl, "STATUS");
}


static int hostapd_cli_cmd_enable(struct wpa_ctrl *ctrl, int argc,
                                  char *argv[])
{
        return hostapd_ctrl_command(ctrl, "ENABLE");
}


static int hostapd_cli_cmd_reload(struct wpa_ctrl *ctrl, int argc,
                                  char *argv[])
{
        return hostapd_ctrl_command(ctrl, "RELOAD");
}


static int hostapd_cli_cmd_disable(struct wpa_ctrl *ctrl, int argc,
                                   char *argv[])
{
        return hostapd_ctrl_command(ctrl, "DISABLE");
}


static int hostapd_cli_cmd_update_beacon(struct wpa_ctrl *ctrl, int argc,
                                         char *argv[])
{
        return hostapd_ctrl_command(ctrl, "UPDATE_BEACON");
}


static int hostapd_cli_cmd_sta(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char buf[64];
	if (argc < 1) {
		printf("Invalid 'sta' command - at least one argument, STA "
		       "address, is required.\n");
		return -1;
	}
	if (argc > 1)
		os_snprintf(buf, sizeof(buf), "STA %s %s", argv[0], argv[1]);
	else
		os_snprintf(buf, sizeof(buf), "STA %s", argv[0]);
	return hostapd_ctrl_command(ctrl, buf);
}


static char ** hostapd_complete_stations(const char *str, int pos)
{
	int arg = get_cmd_arg_num(str, pos);
	char **res = NULL;

	switch (arg) {
	case 1:
		res = cli_txt_list_array(&stations);
		break;
	}

	return res;
}


static int hostapd_cli_cmd_new_sta(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	char buf[64];
	if (argc != 1) {
		printf("Invalid 'new_sta' command - exactly one argument, STA "
		       "address, is required.\n");
		return -1;
	}
	os_snprintf(buf, sizeof(buf), "NEW_STA %s", argv[0]);
	return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_chan_switch(struct wpa_ctrl *ctrl,
                                       int argc, char *argv[])
{
        char cmd[256];
        int res;
        int i;
        char *tmp;
        int total;

        if (argc < 2) {
                printf("Invalid chan_switch command: needs at least two "
                       "arguments (count and freq)\n"
                       "usage: <cs_count> <freq> [sec_channel_offset=] "
                       "[center_freq1=] [center_freq2=] [bandwidth=] "
                       "[blocktx] [ht|vht]\n");
                return -1;
        }

        res = os_snprintf(cmd, sizeof(cmd), "CHAN_SWITCH %s %s",
                          argv[0], argv[1]);
        if (os_snprintf_error(sizeof(cmd), res)) {
                printf("Too long CHAN_SWITCH command.\n");
                return -1;
        }

        total = res;
        for (i = 2; i < argc; i++) {
                tmp = cmd + total;
                res = os_snprintf(tmp, sizeof(cmd) - total, " %s", argv[i]);
                if (os_snprintf_error(sizeof(cmd) - total, res)) {
                        printf("Too long CHAN_SWITCH command.\n");
                        return -1;
                }
                total += res;
        }
        return hostapd_ctrl_command(ctrl, cmd);
}


static int hostapd_cli_cmd_ping(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
        return hostapd_ctrl_command(ctrl, "PING");
}


static int hostapd_cli_cmd_relog(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
        return hostapd_ctrl_command(ctrl, "RELOG");
}


static int hostapd_cli_cmd_mib(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
        if (argc > 0) {
                char buf[100];
                os_snprintf(buf, sizeof(buf), "MIB %s", argv[0]);
                return hostapd_ctrl_command(ctrl, buf);
        }
        return hostapd_ctrl_command(ctrl, "MIB");
}


#ifdef CONFIG_TAXONOMY
static int hostapd_cli_cmd_signature(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	char buf[64];

	if (argc != 1) {
		printf("Invalid 'signature' command - exactly one argument, STA address, is required.\n");
		return -1;
	}
	os_snprintf(buf, sizeof(buf), "SIGNATURE %s", argv[0]);
	return hostapd_ctrl_command(ctrl, buf);
}
#endif /* CONFIG_TAXONOMY */


static int hostapd_cli_cmd_sa_query(struct wpa_ctrl *ctrl, int argc,
				    char *argv[])
{
	char buf[64];
	if (argc != 1) {
		printf("Invalid 'sa_query' command - exactly one argument, "
		       "STA address, is required.\n");
		return -1;
	}
	os_snprintf(buf, sizeof(buf), "SA_QUERY %s", argv[0]);
	return hostapd_ctrl_command(ctrl, buf);
}


#ifdef CONFIG_WPS
static int hostapd_cli_cmd_wps_pin(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	char buf[256];
	if (argc < 2) {
		printf("Invalid 'wps_pin' command - at least two arguments, "
		       "UUID and PIN, are required.\n");
		return -1;
	}
	if (argc > 3)
		os_snprintf(buf, sizeof(buf), "WPS_PIN %s %s %s %s",
			 argv[0], argv[1], argv[2], argv[3]);
	else if (argc > 2)
		os_snprintf(buf, sizeof(buf), "WPS_PIN %s %s %s",
			 argv[0], argv[1], argv[2]);
	else
		os_snprintf(buf, sizeof(buf), "WPS_PIN %s %s", argv[0], argv[1]);
	return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_wps_check_pin(struct wpa_ctrl *ctrl, int argc,
					 char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1 && argc != 2) {
		printf("Invalid WPS_CHECK_PIN command: needs one argument:\n"
		       "- PIN to be verified\n");
		return -1;
	}

	if (argc == 2)
		res = os_snprintf(cmd, sizeof(cmd), "WPS_CHECK_PIN %s %s",
				  argv[0], argv[1]);
	else
		res = os_snprintf(cmd, sizeof(cmd), "WPS_CHECK_PIN %s",
				  argv[0]);
	if (os_snprintf_error(sizeof(cmd), res)) {
		printf("Too long WPS_CHECK_PIN command.\n");
		return -1;
	}
	return hostapd_ctrl_command(ctrl, cmd);
}


static int hostapd_cli_cmd_wps_pbc(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	return hostapd_ctrl_command(ctrl, "WPS_PBC");
}


static int hostapd_cli_cmd_wps_cancel(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	return hostapd_ctrl_command(ctrl, "WPS_CANCEL");
}


#ifdef CONFIG_WPS_NFC
static int hostapd_cli_cmd_wps_nfc_tag_read(struct wpa_ctrl *ctrl, int argc,
					    char *argv[])
{
	int ret;
	char *buf;
	size_t buflen;

	if (argc != 1) {
		printf("Invalid 'wps_nfc_tag_read' command - one argument "
		       "is required.\n");
		return -1;
	}

	buflen = 18 + os_strlen(argv[0]);
	buf = os_malloc(buflen);
	if (buf == NULL)
		return -1;
	os_snprintf(buf, buflen, "WPS_NFC_TAG_READ %s", argv[0]);

	ret = hostapd_ctrl_command(ctrl, buf);
	os_free(buf);

	return ret;
}


static int hostapd_cli_cmd_wps_nfc_config_token(struct wpa_ctrl *ctrl,
						int argc, char *argv[])
{
	char cmd[64];
	int res;

	if (argc != 1) {
		printf("Invalid 'wps_nfc_config_token' command - one argument "
		       "is required.\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "WPS_NFC_CONFIG_TOKEN %s",
			  argv[0]);
	if (os_snprintf_error(sizeof(cmd), res)) {
		printf("Too long WPS_NFC_CONFIG_TOKEN command.\n");
		return -1;
	}
	return hostapd_ctrl_command(ctrl, cmd);
}


static int hostapd_cli_cmd_wps_nfc_token(struct wpa_ctrl *ctrl,
					 int argc, char *argv[])
{
	char cmd[64];
	int res;

	if (argc != 1) {
		printf("Invalid 'wps_nfc_token' command - one argument is "
		       "required.\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "WPS_NFC_TOKEN %s", argv[0]);
	if (os_snprintf_error(sizeof(cmd), res)) {
		printf("Too long WPS_NFC_TOKEN command.\n");
		return -1;
	}
	return hostapd_ctrl_command(ctrl, cmd);
}


static int hostapd_cli_cmd_nfc_get_handover_sel(struct wpa_ctrl *ctrl,
						int argc, char *argv[])
{
	char cmd[64];
	int res;

	if (argc != 2) {
		printf("Invalid 'nfc_get_handover_sel' command - two arguments "
		       "are required.\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "NFC_GET_HANDOVER_SEL %s %s",
			  argv[0], argv[1]);
	if (os_snprintf_error(sizeof(cmd), res)) {
		printf("Too long NFC_GET_HANDOVER_SEL command.\n");
		return -1;
	}
	return hostapd_ctrl_command(ctrl, cmd);
}

#endif /* CONFIG_WPS_NFC */


static int hostapd_cli_cmd_wps_ap_pin(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	char buf[64];
	if (argc < 1) {
		printf("Invalid 'wps_ap_pin' command - at least one argument "
		       "is required.\n");
		return -1;
	}
	if (argc > 2)
		os_snprintf(buf, sizeof(buf), "WPS_AP_PIN %s %s %s",
			 argv[0], argv[1], argv[2]);
	else if (argc > 1)
		os_snprintf(buf, sizeof(buf), "WPS_AP_PIN %s %s",
			 argv[0], argv[1]);
	else
		os_snprintf(buf, sizeof(buf), "WPS_AP_PIN %s", argv[0]);
	return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_wps_get_status(struct wpa_ctrl *ctrl, int argc,
					  char *argv[])
{
	return hostapd_ctrl_command(ctrl, "WPS_GET_STATUS");
}


static int hostapd_cli_cmd_wps_config(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	char buf[256];
	char ssid_hex[2 * SSID_MAX_LEN + 1];
	char key_hex[2 * 64 + 1];
	int i;

	if (argc < 1) {
		printf("Invalid 'wps_config' command - at least two arguments "
		       "are required.\n");
		return -1;
	}

	ssid_hex[0] = '\0';
	for (i = 0; i < SSID_MAX_LEN; i++) {
		if (argv[0][i] == '\0')
			break;
		os_snprintf(&ssid_hex[i * 2], 3, "%02x", argv[0][i]);
	}

	key_hex[0] = '\0';
	if (argc > 3) {
		for (i = 0; i < 64; i++) {
			if (argv[3][i] == '\0')
				break;
			os_snprintf(&key_hex[i * 2], 3, "%02x",
				    argv[3][i]);
		}
	}

	if (argc > 3)
		os_snprintf(buf, sizeof(buf), "WPS_CONFIG %s %s %s %s",
			 ssid_hex, argv[1], argv[2], key_hex);
	else if (argc > 2)
		os_snprintf(buf, sizeof(buf), "WPS_CONFIG %s %s %s",
			 ssid_hex, argv[1], argv[2]);
	else
		os_snprintf(buf, sizeof(buf), "WPS_CONFIG %s %s",
			 ssid_hex, argv[1]);
	return hostapd_ctrl_command(ctrl, buf);
}
#endif /* CONFIG_WPS */


static int hostapd_cli_cmd_disassoc_imminent(struct wpa_ctrl *ctrl, int argc,
					     char *argv[])
{
	char buf[300];
	int res;

	if (argc < 2) {
		printf("Invalid 'disassoc_imminent' command - two arguments "
		       "(STA addr and Disassociation Timer) are needed\n");
		return -1;
	}

	res = os_snprintf(buf, sizeof(buf), "DISASSOC_IMMINENT %s %s",
			  argv[0], argv[1]);
	if (os_snprintf_error(sizeof(buf), res))
		return -1;
	return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_ess_disassoc(struct wpa_ctrl *ctrl, int argc,
					char *argv[])
{
	char buf[300];
	int res;

	if (argc < 3) {
		printf("Invalid 'ess_disassoc' command - three arguments (STA "
		       "addr, disassoc timer, and URL) are needed\n");
		return -1;
	}

	res = os_snprintf(buf, sizeof(buf), "ESS_DISASSOC %s %s %s",
			  argv[0], argv[1], argv[2]);
	if (os_snprintf_error(sizeof(buf), res))
		return -1;
	return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_bss_tm_req(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	char buf[2000], *tmp;
	int res, i, total;

	if (argc < 1) {
		printf("Invalid 'bss_tm_req' command - at least one argument (STA addr) is needed\n");
		return -1;
	}

	res = os_snprintf(buf, sizeof(buf), "BSS_TM_REQ %s", argv[0]);
	if (os_snprintf_error(sizeof(buf), res))
		return -1;

	total = res;
	for (i = 1; i < argc; i++) {
		tmp = &buf[total];
		res = os_snprintf(tmp, sizeof(buf) - total, " %s", argv[i]);
		if (os_snprintf_error(sizeof(buf) - total, res))
			return -1;
		total += res;
	}
	return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_get_config(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	return hostapd_ctrl_command(ctrl, "GET_CONFIG");
}


static int wpa_ctrl_command_sta(struct wpa_ctrl *ctrl, const char *cmd,
				char *addr, size_t addr_len, int print)
{
	char buf[1024], *pos;
	size_t len;
	int ret;

	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len,
			       hostapd_cli_msg_cb);
	if (ret == -2) {
		printf("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		printf("'%s' command failed.\n", cmd);
		return -1;
	}

	buf[len] = '\0';
	if (memcmp(buf, "FAIL", 4) == 0)
		return -1;
	if (print)
		printf("%s", buf);

	pos = buf;
	while (*pos != '\0' && *pos != '\n')
		pos++;
	*pos = '\0';
	os_strlcpy(addr, buf, addr_len);
	return 0;
}


static int hostapd_cli_cmd_all_sta(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	char addr[32], cmd[64];

	if (wpa_ctrl_command_sta(ctrl, "STA-FIRST", addr, sizeof(addr), 1))
		return 0;
	do {
		os_snprintf(cmd, sizeof(cmd), "STA-NEXT %s", addr);
	} while (wpa_ctrl_command_sta(ctrl, cmd, addr, sizeof(addr), 1) == 0);

	return -1;
}


static int hostapd_cli_cmd_list_sta(struct wpa_ctrl *ctrl, int argc,
				    char *argv[])
{
	char addr[32], cmd[64];

	if (wpa_ctrl_command_sta(ctrl, "STA-FIRST", addr, sizeof(addr), 0))
		return 0;
	do {
		if (os_strcmp(addr, "") != 0)
			printf("%s\n", addr);
		os_snprintf(cmd, sizeof(cmd), "STA-NEXT %s", addr);
	} while (wpa_ctrl_command_sta(ctrl, cmd, addr, sizeof(addr), 0) == 0);

	return 0;
}


static int hostapd_cli_cmd_set_qos_map_set(struct wpa_ctrl *ctrl,
					   int argc, char *argv[])
{
	char buf[200];
	int res;

	if (argc != 1) {
		printf("Invalid 'set_qos_map_set' command - "
		       "one argument (comma delimited QoS map set) "
		       "is needed\n");
		return -1;
	}

	res = os_snprintf(buf, sizeof(buf), "SET_QOS_MAP_SET %s", argv[0]);
	if (os_snprintf_error(sizeof(buf), res))
		return -1;
	return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_send_qos_map_conf(struct wpa_ctrl *ctrl,
					     int argc, char *argv[])
{
	char buf[50];
	int res;

	if (argc != 1) {
		printf("Invalid 'send_qos_map_conf' command - "
		       "one argument (STA addr) is needed\n");
		return -1;
	}

	res = os_snprintf(buf, sizeof(buf), "SEND_QOS_MAP_CONF %s", argv[0]);
	if (os_snprintf_error(sizeof(buf), res))
		return -1;
	return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_hs20_wnm_notif(struct wpa_ctrl *ctrl, int argc,
					  char *argv[])
{
	char buf[300];
	int res;

	if (argc < 2) {
		printf("Invalid 'hs20_wnm_notif' command - two arguments (STA "
		       "addr and URL) are needed\n");
		return -1;
	}

	res = os_snprintf(buf, sizeof(buf), "HS20_WNM_NOTIF %s %s",
			  argv[0], argv[1]);
	if (os_snprintf_error(sizeof(buf), res))
		return -1;
	return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_hs20_deauth_req(struct wpa_ctrl *ctrl, int argc,
					   char *argv[])
{
	char buf[300];
	int res;

	if (argc < 3) {
		printf("Invalid 'hs20_deauth_req' command - at least three arguments (STA addr, Code, Re-auth Delay) are needed\n");
		return -1;
	}

	if (argc > 3)
		res = os_snprintf(buf, sizeof(buf),
				  "HS20_DEAUTH_REQ %s %s %s %s",
				  argv[0], argv[1], argv[2], argv[3]);
	else
		res = os_snprintf(buf, sizeof(buf),
				  "HS20_DEAUTH_REQ %s %s %s",
				  argv[0], argv[1], argv[2]);
	if (os_snprintf_error(sizeof(buf), res))
		return -1;
	return hostapd_ctrl_command(ctrl, buf);
}


static int hostapd_cli_cmd_get(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid GET command: needs one argument (variable "
		       "name)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "GET %s", argv[0]);
	if (os_snprintf_error(sizeof(cmd), res)) {
		printf("Too long GET command.\n");
		return -1;
	}
	return hostapd_ctrl_command(ctrl, cmd);
}


static char ** hostapd_complete_get(const char *str, int pos)
{
	int arg = get_cmd_arg_num(str, pos);
	const char *fields[] = {
		"version", "tls_library",
	};
	int i, num_fields = ARRAY_SIZE(fields);

	if (arg == 1) {
		char **res;

		res = os_calloc(num_fields + 1, sizeof(char *));
		if (!res)
			return NULL;
		for (i = 0; i < num_fields; i++) {
			res[i] = os_strdup(fields[i]);
			if (!res[i])
				return res;
		}
		return res;
	}
	return NULL;
}


#ifdef CONFIG_FST
static int hostapd_cli_cmd_fst(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;
	int i;
	int total;

	if (argc <= 0) {
		printf("FST command: parameters are required.\n");
		return -1;
	}

	total = os_snprintf(cmd, sizeof(cmd), "FST-MANAGER");

	for (i = 0; i < argc; i++) {
		res = os_snprintf(cmd + total, sizeof(cmd) - total, " %s",
				  argv[i]);
		if (os_snprintf_error(sizeof(cmd) - total, res)) {
			printf("Too long fst command.\n");
			return -1;
		}
		total += res;
	}
	return hostapd_ctrl_command(ctrl, cmd);
}
#endif /* CONFIG_FST */


static int hostapd_cli_cmd_vendor(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc < 2 || argc > 4) {
		printf("Invalid vendor command\n"
		       "usage: <vendor id> <command id> [<hex formatted command argument>] [nested=<0|1>]\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "VENDOR %s %s %s%s%s", argv[0],
			  argv[1], argc >= 3 ? argv[2] : "",
			  argc == 4 ? " " : "", argc == 4 ? argv[3] : "");
	if (os_snprintf_error(sizeof(cmd), res)) {
		printf("Too long VENDOR command.\n");
		return -1;
	}
	return hostapd_ctrl_command(ctrl, cmd);
}


static int hostapd_cli_cmd_erp_flush(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	return hostapd_ctrl_command(ctrl, "ERP_FLUSH");
}


static int hostapd_cli_cmd_log_level(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	char cmd[256];
	int res;

	res = os_snprintf(cmd, sizeof(cmd), "LOG_LEVEL%s%s%s%s",
			  argc >= 1 ? " " : "",
			  argc >= 1 ? argv[0] : "",
			  argc == 2 ? " " : "",
			  argc == 2 ? argv[1] : "");
	if (os_snprintf_error(sizeof(cmd), res)) {
		printf("Too long option\n");
		return -1;
	}
	return hostapd_ctrl_command(ctrl, cmd);
}


static int hostapd_cli_cmd_raw(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	if (argc == 0)
		return -1;
	return hostapd_cli_cmd(ctrl, argv[0], 0, argc - 1, &argv[1]);
}


static int hostapd_cli_cmd_pmksa(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	return hostapd_ctrl_command(ctrl, "PMKSA");
}


static int hostapd_cli_cmd_pmksa_flush(struct wpa_ctrl *ctrl, int argc,
				       char *argv[])
{
	return hostapd_ctrl_command(ctrl, "PMKSA_FLUSH");
}


static int hostapd_cli_cmd_set_neighbor(struct wpa_ctrl *ctrl, int argc,
					char *argv[])
{
	char cmd[2048];
	int res;

	if (argc < 3 || argc > 6) {
		printf("Invalid set_neighbor command: needs 3-6 arguments\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "SET_NEIGHBOR %s %s %s %s %s %s",
			  argv[0], argv[1], argv[2], argc >= 4 ? argv[3] : "",
			  argc >= 5 ? argv[4] : "", argc == 6 ? argv[5] : "");
	if (os_snprintf_error(sizeof(cmd), res)) {
		printf("Too long SET_NEIGHBOR command.\n");
		return -1;
	}
	return hostapd_ctrl_command(ctrl, cmd);
}


static int hostapd_cli_cmd_show_neighbor(struct wpa_ctrl *ctrl, int argc,
					 char *argv[])
{
	return hostapd_ctrl_command(ctrl, "SHOW_NEIGHBOR");
}


static int hostapd_cli_cmd_remove_neighbor(struct wpa_ctrl *ctrl, int argc,
					   char *argv[])
{
	return hostapd_cli_cmd(ctrl, "REMOVE_NEIGHBOR", 1, argc, argv);
}


static int hostapd_cli_cmd_req_lci(struct wpa_ctrl *ctrl, int argc,
				   char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid req_lci command - requires destination address\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "REQ_LCI %s", argv[0]);
	if (os_snprintf_error(sizeof(cmd), res)) {
		printf("Too long REQ_LCI command.\n");
		return -1;
	}
	return hostapd_ctrl_command(ctrl, cmd);
}


static int hostapd_cli_cmd_req_range(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	if (argc < 4) {
		printf("Invalid req_range command: needs at least 4 arguments - dest address, randomization interval, min AP count, and 1 to 16 AP addresses\n");
		return -1;
	}

	return hostapd_cli_cmd(ctrl, "REQ_RANGE", 4, argc, argv);
}


static int hostapd_cli_cmd_driver_flags(struct wpa_ctrl *ctrl, int argc,
					char *argv[])
{
	return hostapd_ctrl_command(ctrl, "DRIVER_FLAGS");
}


#ifdef CONFIG_DPP

static int hostapd_cli_cmd_dpp_qr_code(struct wpa_ctrl *ctrl, int argc,
				       char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_QR_CODE", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_bootstrap_gen(struct wpa_ctrl *ctrl, int argc,
					     char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_BOOTSTRAP_GEN", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_bootstrap_remove(struct wpa_ctrl *ctrl, int argc,
						char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_BOOTSTRAP_REMOVE", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_bootstrap_get_uri(struct wpa_ctrl *ctrl,
						 int argc, char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_BOOTSTRAP_GET_URI", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_bootstrap_info(struct wpa_ctrl *ctrl, int argc,
					      char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_BOOTSTRAP_INFO", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_bootstrap_set(struct wpa_ctrl *ctrl, int argc,
					     char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_BOOTSTRAP_SET", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_auth_init(struct wpa_ctrl *ctrl, int argc,
					 char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_AUTH_INIT", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_listen(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_LISTEN", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_stop_listen(struct wpa_ctrl *ctrl, int argc,
					   char *argv[])
{
	return hostapd_ctrl_command(ctrl, "DPP_STOP_LISTEN");
}


static int hostapd_cli_cmd_dpp_configurator_add(struct wpa_ctrl *ctrl, int argc,
						char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_CONFIGURATOR_ADD", 0, argc, argv);
}


static int hostapd_cli_cmd_dpp_configurator_remove(struct wpa_ctrl *ctrl,
						   int argc, char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_CONFIGURATOR_REMOVE", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_configurator_get_key(struct wpa_ctrl *ctrl,
						    int argc, char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_CONFIGURATOR_GET_KEY", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_configurator_sign(struct wpa_ctrl *ctrl,
						 int argc, char *argv[])
{
       return hostapd_cli_cmd(ctrl, "DPP_CONFIGURATOR_SIGN", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_pkex_add(struct wpa_ctrl *ctrl, int argc,
					char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_PKEX_ADD", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_pkex_remove(struct wpa_ctrl *ctrl, int argc,
					   char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_PKEX_REMOVE", 1, argc, argv);
}


#ifdef CONFIG_DPP2

static int hostapd_cli_cmd_dpp_controller_start(struct wpa_ctrl *ctrl, int argc,
						char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_CONTROLLER_START", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_controller_stop(struct wpa_ctrl *ctrl, int argc,
					       char *argv[])
{
	return hostapd_ctrl_command(ctrl, "DPP_CONTROLLER_STOP");
}


static int hostapd_cli_cmd_dpp_chirp(struct wpa_ctrl *ctrl, int argc,
				     char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DPP_CHIRP", 1, argc, argv);
}


static int hostapd_cli_cmd_dpp_stop_chirp(struct wpa_ctrl *ctrl, int argc,
					  char *argv[])
{
	return hostapd_ctrl_command(ctrl, "DPP_STOP_CHIRP");
}

#endif /* CONFIG_DPP2 */
#endif /* CONFIG_DPP */


static int hostapd_cli_cmd_accept_macacl(struct wpa_ctrl *ctrl, int argc,
					 char *argv[])
{
	return hostapd_cli_cmd(ctrl, "ACCEPT_ACL", 1, argc, argv);
}


static int hostapd_cli_cmd_deny_macacl(struct wpa_ctrl *ctrl, int argc,
				       char *argv[])
{
	return hostapd_cli_cmd(ctrl, "DENY_ACL", 1, argc, argv);
}


static int hostapd_cli_cmd_poll_sta(struct wpa_ctrl *ctrl, int argc,
				    char *argv[])
{
	return hostapd_cli_cmd(ctrl, "POLL_STA", 1, argc, argv);
}


static int hostapd_cli_cmd_req_beacon(struct wpa_ctrl *ctrl, int argc,
				      char *argv[])
{
	return hostapd_cli_cmd(ctrl, "REQ_BEACON", 2, argc, argv);
}


static int hostapd_cli_cmd_reload_wpa_psk(struct wpa_ctrl *ctrl, int argc,
					  char *argv[])
{
	return hostapd_ctrl_command(ctrl, "RELOAD_WPA_PSK");
}


struct hostapd_cli_cmd {
	const char *cmd;
	int (*handler)(struct wpa_ctrl *ctrl, int argc, char *argv[]);
	char ** (*completion)(const char *str, int pos);
	const char *usage;
};

static const struct hostapd_cli_cmd hostapd_cli_commands[] = {
	{ "status", hostapd_cli_cmd_status, NULL,
	  "= show interface status info" },
	{ "set", hostapd_cli_cmd_set, hostapd_complete_set,
	  "<name> <value> = set runtime variables" },
	{ "sta", hostapd_cli_cmd_sta, hostapd_complete_stations,
	  "<addr> = get MIB variables for one station" },
	{ "all_sta", hostapd_cli_cmd_all_sta, NULL,
	   "= get MIB variables for all stations" },
	{ "list_sta", hostapd_cli_cmd_list_sta, NULL,
	   "= list all stations" },
	{ "new_sta", hostapd_cli_cmd_new_sta, NULL,
	  "<addr> = add a new station" },
	{ "deauthenticate", hostapd_cli_cmd_deauthenticate,
	  hostapd_complete_stations,
	  "<addr> = deauthenticate a station" },
	{ "disassociate", hostapd_cli_cmd_disassociate,
	  hostapd_complete_stations,
	  "<addr> = disassociate a station" },
	{ "enable", hostapd_cli_cmd_enable, NULL,
	  "= enable hostapd on current interface" },
	{ "reload", hostapd_cli_cmd_reload, NULL,
	  "= reload configuration for current interface" },
	{ "disable", hostapd_cli_cmd_disable, NULL,
	  "= disable hostapd on current interface" },
	{ "update_beacon", hostapd_cli_cmd_update_beacon, NULL,
	  "= update Beacon frame contents\n"},
	{ "chan_switch", hostapd_cli_cmd_chan_switch, NULL,
	  "<cs_count> <freq> [sec_channel_offset=] [center_freq1=]\n"
	  "  [center_freq2=] [bandwidth=] [blocktx] [ht|vht]\n"
	  "  = initiate channel switch announcement" },
	{ "ping", hostapd_cli_cmd_ping, NULL,
	  "= pings hostapd" },
	{ "mib", hostapd_cli_cmd_mib, NULL,
	  "= get MIB variables (dot1x, dot11, radius)" },
	{ "relog", hostapd_cli_cmd_relog, NULL,
	  "= reload/truncate debug log output file" },
#ifdef CONFIG_TAXONOMY
	{ "signature", hostapd_cli_cmd_signature, hostapd_complete_stations,
	  "<addr> = get taxonomy signature for a station" },
#endif /* CONFIG_TAXONOMY */
	{ "sa_query", hostapd_cli_cmd_sa_query, hostapd_complete_stations,
	  "<addr> = send SA Query to a station" },
#ifdef CONFIG_WPS
	{ "wps_pin", hostapd_cli_cmd_wps_pin, NULL,
	  "<uuid> <pin> [timeout] [addr] = add WPS Enrollee PIN" },
	{ "wps_check_pin", hostapd_cli_cmd_wps_check_pin, NULL,
	  "<PIN> = verify PIN checksum" },
	{ "wps_pbc", hostapd_cli_cmd_wps_pbc, NULL,
	  "= indicate button pushed to initiate PBC" },
	{ "wps_cancel", hostapd_cli_cmd_wps_cancel, NULL,
	  "= cancel the pending WPS operation" },
#ifdef CONFIG_WPS_NFC
	{ "wps_nfc_tag_read", hostapd_cli_cmd_wps_nfc_tag_read, NULL,
	  "<hexdump> = report read NFC tag with WPS data" },
	{ "wps_nfc_config_token", hostapd_cli_cmd_wps_nfc_config_token, NULL,
	  "<WPS/NDEF> = build NFC configuration token" },
	{ "wps_nfc_token", hostapd_cli_cmd_wps_nfc_token, NULL,
	  "<WPS/NDEF/enable/disable> = manager NFC password token" },
	{ "nfc_get_handover_sel", hostapd_cli_cmd_nfc_get_handover_sel, NULL,
	  NULL },
#endif /* CONFIG_WPS_NFC */
	{ "wps_ap_pin", hostapd_cli_cmd_wps_ap_pin, NULL,
	  "<cmd> [params..] = enable/disable AP PIN" },
	{ "wps_config", hostapd_cli_cmd_wps_config, NULL,
	  "<SSID> <auth> <encr> <key> = configure AP" },
	{ "wps_get_status", hostapd_cli_cmd_wps_get_status, NULL,
	  "= show current WPS status" },
#endif /* CONFIG_WPS */
	{ "disassoc_imminent", hostapd_cli_cmd_disassoc_imminent, NULL,
	  "= send Disassociation Imminent notification" },
	{ "ess_disassoc", hostapd_cli_cmd_ess_disassoc, NULL,
	  "= send ESS Dissassociation Imminent notification" },
	{ "bss_tm_req", hostapd_cli_cmd_bss_tm_req, NULL,
	  "= send BSS Transition Management Request" },
	{ "get_config", hostapd_cli_cmd_get_config, NULL,
	  "= show current configuration" },
#ifdef CONFIG_FST
	{ "fst", hostapd_cli_cmd_fst, NULL,
	  "<params...> = send FST-MANAGER control interface command" },
#endif /* CONFIG_FST */
	{ "raw", hostapd_cli_cmd_raw, NULL,
	  "<params..> = send unprocessed command" },
	{ "get", hostapd_cli_cmd_get, hostapd_complete_get,
	  "<name> = get runtime info" },
	{ "set_qos_map_set", hostapd_cli_cmd_set_qos_map_set, NULL,
	  "<arg,arg,...> = set QoS Map set element" },
	{ "send_qos_map_conf", hostapd_cli_cmd_send_qos_map_conf,
	  hostapd_complete_stations,
	  "<addr> = send QoS Map Configure frame" },
	{ "hs20_wnm_notif", hostapd_cli_cmd_hs20_wnm_notif, NULL,
	  "<addr> <url>\n"
	  "  = send WNM-Notification Subscription Remediation Request" },
	{ "hs20_deauth_req", hostapd_cli_cmd_hs20_deauth_req, NULL,
	  "<addr> <code (0/1)> <Re-auth-Delay(sec)> [url]\n"
	  "  = send WNM-Notification imminent deauthentication indication" },
	{ "vendor", hostapd_cli_cmd_vendor, NULL,
	  "<vendor id> <sub command id> [<hex formatted data>]\n"
	  "  = send vendor driver command" },
	{ "erp_flush", hostapd_cli_cmd_erp_flush, NULL,
	  "= drop all ERP keys"},
	{ "log_level", hostapd_cli_cmd_log_level, NULL,
	  "[level] = show/change log verbosity level" },
	{ "pmksa", hostapd_cli_cmd_pmksa, NULL,
	  " = show PMKSA cache entries" },
	{ "pmksa_flush", hostapd_cli_cmd_pmksa_flush, NULL,
	  " = flush PMKSA cache" },
	{ "set_neighbor", hostapd_cli_cmd_set_neighbor, NULL,
	  "<addr> <ssid=> <nr=> [lci=] [civic=] [stat]\n"
	  "  = add AP to neighbor database" },
	{ "show_neighbor", hostapd_cli_cmd_show_neighbor, NULL,
	  "  = show neighbor database entries" },
	{ "remove_neighbor", hostapd_cli_cmd_remove_neighbor, NULL,
	  "<addr> [ssid=<hex>] = remove AP from neighbor database" },
	{ "req_lci", hostapd_cli_cmd_req_lci, hostapd_complete_stations,
	  "<addr> = send LCI request to a station"},
	{ "req_range", hostapd_cli_cmd_req_range, NULL,
	  " = send FTM range request"},
	{ "driver_flags", hostapd_cli_cmd_driver_flags, NULL,
	  " = show supported driver flags"},
#ifdef CONFIG_DPP
	{ "dpp_qr_code", hostapd_cli_cmd_dpp_qr_code, NULL,
	  "report a scanned DPP URI from a QR Code" },
	{ "dpp_bootstrap_gen", hostapd_cli_cmd_dpp_bootstrap_gen, NULL,
	  "type=<qrcode> [chan=..] [mac=..] [info=..] [curve=..] [key=..] = generate DPP bootstrap information" },
	{ "dpp_bootstrap_remove", hostapd_cli_cmd_dpp_bootstrap_remove, NULL,
	  "*|<id> = remove DPP bootstrap information" },
	{ "dpp_bootstrap_get_uri", hostapd_cli_cmd_dpp_bootstrap_get_uri, NULL,
	  "<id> = get DPP bootstrap URI" },
	{ "dpp_bootstrap_info", hostapd_cli_cmd_dpp_bootstrap_info, NULL,
	  "<id> = show DPP bootstrap information" },
	{ "dpp_bootstrap_set", hostapd_cli_cmd_dpp_bootstrap_set, NULL,
	  "<id> [conf=..] [ssid=<SSID>] [ssid_charset=#] [psk=<PSK>] [pass=<passphrase>] [configurator=<id>] [conn_status=#] [akm_use_selector=<0|1>] [group_id=..] [expiry=#] [csrattrs=..] = set DPP configurator parameters" },
	{ "dpp_auth_init", hostapd_cli_cmd_dpp_auth_init, NULL,
	  "peer=<id> [own=<id>] = initiate DPP bootstrapping" },
	{ "dpp_listen", hostapd_cli_cmd_dpp_listen, NULL,
	  "<freq in MHz> = start DPP listen" },
	{ "dpp_stop_listen", hostapd_cli_cmd_dpp_stop_listen, NULL,
	  "= stop DPP listen" },
	{ "dpp_configurator_add", hostapd_cli_cmd_dpp_configurator_add, NULL,
	  "[curve=..] [key=..] = add DPP configurator" },
	{ "dpp_configurator_remove", hostapd_cli_cmd_dpp_configurator_remove,
	  NULL,
	  "*|<id> = remove DPP configurator" },
	{ "dpp_configurator_get_key", hostapd_cli_cmd_dpp_configurator_get_key,
	  NULL,
	  "<id> = Get DPP configurator's private key" },
	{ "dpp_configurator_sign", hostapd_cli_cmd_dpp_configurator_sign, NULL,
	  "conf=<role> configurator=<id> = generate self DPP configuration" },
	{ "dpp_pkex_add", hostapd_cli_cmd_dpp_pkex_add, NULL,
	  "add PKEX code" },
	{ "dpp_pkex_remove", hostapd_cli_cmd_dpp_pkex_remove, NULL,
	  "*|<id> = remove DPP pkex information" },
#ifdef CONFIG_DPP2
	{ "dpp_controller_start", hostapd_cli_cmd_dpp_controller_start, NULL,
	  "[tcp_port=<port>] [role=..] = start DPP controller" },
	{ "dpp_controller_stop", hostapd_cli_cmd_dpp_controller_stop, NULL,
	  "= stop DPP controller" },
	{ "dpp_chirp", hostapd_cli_cmd_dpp_chirp, NULL,
	  "own=<BI ID> iter=<count> = start DPP chirp" },
	{ "dpp_stop_chirp", hostapd_cli_cmd_dpp_stop_chirp, NULL,
	  "= stop DPP chirp" },
#endif /* CONFIG_DPP2 */
#endif /* CONFIG_DPP */
	{ "accept_acl", hostapd_cli_cmd_accept_macacl, NULL,
	  "=Add/Delete/Show/Clear accept MAC ACL" },
	{ "deny_acl", hostapd_cli_cmd_deny_macacl, NULL,
	  "=Add/Delete/Show/Clear deny MAC ACL" },
	{ "poll_sta", hostapd_cli_cmd_poll_sta, hostapd_complete_stations,
	  "<addr> = poll a STA to check connectivity with a QoS null frame" },
	{ "req_beacon", hostapd_cli_cmd_req_beacon, NULL,
	  "<addr> [req_mode=] <measurement request hexdump>  = send a Beacon report request to a station" },
	{ "reload_wpa_psk", hostapd_cli_cmd_reload_wpa_psk, NULL,
	  "= reload wpa_psk_file only" },
	{ NULL, NULL, NULL, NULL }
};

int hostapd_request(struct wpa_ctrl *ctrl, int argc, char *argv[])
{
	const struct hostapd_cli_cmd *cmd, *match = NULL;
	int count;
	int ret = 0;

	count = 0;
	cmd = hostapd_cli_commands;
	while (cmd->cmd) {
		if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) == 0) {
			match = cmd;
			if (os_strcasecmp(cmd->cmd, argv[0]) == 0) {
				/* we have an exact match */
				count = 1;
				break;
			}
			count++;
		}
		cmd++;
	}

	if (count > 1) {
		printf("Ambiguous command '%s'; possible commands:", argv[0]);
		cmd = hostapd_cli_commands;
		while (cmd->cmd) {
			if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) ==
			    0) {
				printf(" %s", cmd->cmd);
			}
			cmd++;
		}
		printf("\n");
		ret = 1;
	} else if (count == 0) {
		printf("Unknown command '%s'\n", argv[0]);
		ret = 1;
	} else {
		ret = match->handler(ctrl, argc - 1, &argv[1]);
	}
	return ret;
}

