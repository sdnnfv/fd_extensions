/*
 *   KAMOME Engineering, Inc. Confidential
 *
 *   Source Materials
 *
 *   Copyright (C) 2014 KAMOME Engineering, Inc. All Rights Reserved.
 *   LICENSED MATERIAL - PROGRAM PROPERTY OF KAMOME Engineering, Inc.
 *
 *   The source code for this program is not published or otherwise
 *   divested of its trade secrets.
 */

#include <dirent.h>
#include <inttypes.h>

#include "pcef.h"

static struct session *session = NULL;

static int handle_pcef_req(struct msg **msg, struct avp *avp, struct session *sess, void *opaque, enum disp_action *act)
{
	// TODO
	return 0;
}

static int install_charging_rule(struct msg *msg)
{
	int rc;
	struct avp *charging_rule_install_avp = NULL;
	struct avp *charging_rule_name_avp = NULL;
	union avp_value *charging_rule_name_avp_value = NULL;
	struct charging_rule *rule = NULL;
	struct sess_state *state = NULL;

	/* Charging-Rule-Install */
	CHECK_FCT_DO(rc = fd_msg_search_avp(msg, pcef_dict->charging_rule_install, &charging_rule_install_avp), goto cleanup);
	if (charging_rule_install_avp == NULL) {
		return 0;
	}

	/* Charging-Rule-Name */
	CHECK_FCT_DO(rc = pcef_msg_search_avp_from_group_avp(charging_rule_install_avp, pcef_dict->charging_rule_name, &charging_rule_name_avp), goto cleanup);
	if (charging_rule_name_avp == NULL) {
		return 0;
	}

	CHECK_FCT_DO(rc = pcef_msg_avp_value_get(charging_rule_name_avp, &charging_rule_name_avp_value), goto cleanup);

	CHECK_FCT_DO(rc = pcef_charging_rule_new(charging_rule_name_avp_value->os.data, charging_rule_name_avp_value->os.len, &rule), goto cleanup);

	CHECK_FCT_DO(rc = pcef_sess_state_retrieve(session, &state), goto cleanup);
	CHECK_FCT_DO(rc = pcef_charging_rule_add(&state->charging_rule_list, rule), goto cleanup);
	CHECK_FCT_DO(rc = pcef_sess_state_store(session, state), goto cleanup);

	return 0;

cleanup:
	pcef_charging_rule_free(rule);
	pcef_sess_state_free(state);
	return rc;
}

static int remove_charging_rule(struct msg *msg)
{
	int rc;
	struct avp *charging_rule_remove_avp = NULL;
	struct avp *charging_rule_name_avp = NULL;
	union avp_value *charging_rule_name_avp_value = NULL;
	struct charging_rule *rule = NULL;
	struct sess_state *state = NULL;

	/* Charging-Rule-Remove */
	CHECK_FCT_DO(rc = fd_msg_search_avp(msg, pcef_dict->charging_rule_remove, &charging_rule_remove_avp), goto cleanup);
	if (charging_rule_remove_avp == NULL) {
		return 0;
	}

	/* Charging-Rule-Name */
	CHECK_FCT_DO(rc = pcef_msg_search_avp_from_group_avp(charging_rule_remove_avp, pcef_dict->charging_rule_name, &charging_rule_name_avp), goto cleanup);
	if (charging_rule_name_avp == NULL) {
		return 0;
	}

	CHECK_FCT_DO(rc = pcef_msg_avp_value_get(charging_rule_name_avp, &charging_rule_name_avp_value), goto cleanup);

	CHECK_FCT_DO(rc = pcef_charging_rule_new(charging_rule_name_avp_value->os.data, charging_rule_name_avp_value->os.len, &rule), goto cleanup);

	CHECK_FCT_DO(rc = pcef_sess_state_retrieve(session, &state), goto cleanup);
	CHECK_FCT_DO(rc = pcef_charging_rule_remove(&state->charging_rule_list, rule), goto cleanup);
	CHECK_FCT_DO(rc = pcef_sess_state_store(session, state), goto cleanup);

	return 0;

cleanup:
	pcef_charging_rule_free(rule);
	pcef_sess_state_free(state);
	return rc;
}

static int set_cc_octets(struct msg *msg)
{
	int rc;
	struct avp *usage_monitoring_information_avp = NULL;
	struct avp *monitoring_key_avp = NULL;
	struct avp *granted_service_unit_avp = NULL;
	struct avp *cc_total_octets_avp = NULL;
	struct avp *cc_input_octets_avp = NULL;
	struct avp *cc_output_octets_avp = NULL;
	union avp_value *avp_value = NULL;
	struct sess_state *state = NULL;

	/* Usage-Monitoring-Information */
	CHECK_FCT_DO(rc = fd_msg_search_avp(msg, pcef_dict->usage_monitoring_information, &usage_monitoring_information_avp), goto cleanup);
	if (usage_monitoring_information_avp == NULL) {
		return 0;
	}

	/* Monitoring-Key */
	CHECK_FCT_DO(rc = pcef_msg_search_avp_from_group_avp(usage_monitoring_information_avp, pcef_dict->monitoring_key, &monitoring_key_avp), goto cleanup);
	if (monitoring_key_avp != NULL) {
		CHECK_FCT_DO(rc = pcef_msg_avp_value_get(monitoring_key_avp, &avp_value), goto cleanup);
		CHECK_FCT_DO(rc = pcef_sess_state_retrieve(session, &state), goto cleanup);
		CHECK_MALLOC_DO(state->monitoring_key = (char *) os0dup(avp_value->os.data, avp_value->os.len), {
			rc = ENOMEM;
			goto cleanup;
		});
		CHECK_FCT_DO(rc = pcef_sess_state_store(session, state), goto cleanup);
	}

	/* Granted-Service-Unit */
	CHECK_FCT_DO(rc = pcef_msg_search_avp_from_group_avp(usage_monitoring_information_avp, pcef_dict->granted_service_unit, &granted_service_unit_avp), goto cleanup);
	if (granted_service_unit_avp == NULL) {
		return 0;
	}

	/* CC-Total-Octets */
	CHECK_FCT_DO(rc = pcef_msg_search_avp_from_group_avp(granted_service_unit_avp, pcef_dict->cc_total_octets, &cc_total_octets_avp), goto cleanup);
	if (cc_total_octets_avp != NULL) {
		CHECK_FCT_DO(rc = pcef_msg_avp_value_get(cc_total_octets_avp, &avp_value), goto cleanup);
		CHECK_FCT_DO(rc = pcef_sess_state_retrieve(session, &state), goto cleanup);
		state->total_octets_threshold = avp_value->u64;
		CHECK_FCT_DO(rc = pcef_sess_state_store(session, state), goto cleanup);
	}

	/* CC-Input-Octets */
	CHECK_FCT_DO(rc = pcef_msg_search_avp_from_group_avp(granted_service_unit_avp, pcef_dict->cc_input_octets, &cc_input_octets_avp), goto cleanup);
	if (cc_input_octets_avp != NULL) {
		CHECK_FCT_DO(rc = pcef_msg_avp_value_get(cc_input_octets_avp, &avp_value), goto cleanup);
		CHECK_FCT_DO(rc = pcef_sess_state_retrieve(session, &state), goto cleanup);
		state->input_octets_threshold = avp_value->u64;
		CHECK_FCT_DO(rc = pcef_sess_state_store(session, state), goto cleanup);
	}

	/* CC-Output-Octets */
	CHECK_FCT_DO(rc = pcef_msg_search_avp_from_group_avp(granted_service_unit_avp, pcef_dict->cc_output_octets, &cc_output_octets_avp), goto cleanup);
	if (cc_output_octets_avp != NULL) {
		CHECK_FCT_DO(rc = pcef_msg_avp_value_get(cc_output_octets_avp, &avp_value), goto cleanup);
		CHECK_FCT_DO(rc = pcef_sess_state_retrieve(session, &state), goto cleanup);
		state->output_octets_threshold = avp_value->u64;
		CHECK_FCT_DO(rc = pcef_sess_state_store(session, state), goto cleanup);
	}

	return 0;

cleanup:
	pcef_sess_state_free(state);
	return rc;
}

static int remove_monitoring_info()
{
	int rc;
	struct sess_state *state = NULL;

	CHECK_FCT_DO(rc = pcef_sess_state_retrieve(session, &state), goto cleanup);
	free(state->monitoring_key);
	state->monitoring_key = NULL;
	state->total_octets_threshold = 0;
	state->input_octets_threshold = 0;
	state->output_octets_threshold = 0;
	CHECK_FCT_DO(rc = pcef_sess_state_store(session, state), goto cleanup);

	return 0;

cleanup:
	pcef_sess_state_free(state);
	return rc;
}

static void receive_init_ans_cb(void *data, struct msg **ans)
{
	LOG_N("Received initial answer.");
	CHECK_FCT_DO(install_charging_rule(*ans), goto cleanup);
	CHECK_FCT_DO(remove_charging_rule(*ans), goto cleanup);
	CHECK_FCT_DO(set_cc_octets(*ans), goto cleanup);

	if (*ans) {
		CHECK_FCT_DO(fd_msg_free(*ans), /* continue */);
		*ans = NULL;
	}

	return;

cleanup:
	if (*ans) {
		CHECK_FCT_DO(fd_msg_free(*ans), /* continue */);
		*ans = NULL;
	}
}

static void send_init_req()
{
	struct msg *req = NULL;

	CHECK_FCT_DO(pcef_msg_init_req_new(session, &req), goto cleanup);
	LOG_N("Sending initial request...");
	CHECK_FCT_DO(fd_msg_send(&req, receive_init_ans_cb, NULL), goto cleanup);

	return;

cleanup:
	return;
}

static void receive_update_ans_cb(void *data, struct msg **ans)
{
	LOG_N("Received update answer.");
	CHECK_FCT_DO(install_charging_rule(*ans), goto cleanup);
	CHECK_FCT_DO(remove_charging_rule(*ans), goto cleanup);
	CHECK_FCT_DO(set_cc_octets(*ans), goto cleanup);
	CHECK_FCT_DO(remove_monitoring_info(), goto cleanup);

	if (*ans) {
		CHECK_FCT_DO(fd_msg_free(*ans), /* continue */);
		*ans = NULL;
	}

	return;

cleanup:
	if (*ans) {
		CHECK_FCT_DO(fd_msg_free(*ans), /* continue */);
		*ans = NULL;
	}
}

static void send_update_req()
{
	struct msg *req = NULL;

	CHECK_FCT_DO(pcef_msg_update_req_new(session, &req), goto cleanup);
	LOG_N("Sending update request...");
	CHECK_FCT_DO(fd_msg_send(&req, receive_update_ans_cb, NULL), goto cleanup);

	return;

cleanup:
	return;
}

static void update_usage(char *update_type)
{
	struct sess_state *state = NULL;

	CHECK_FCT_DO(pcef_sess_state_retrieve(session, &state), goto cleanup);
	if (state->monitoring_key == NULL) {
		LOG_N("User session monitoring is not started.");
		CHECK_FCT_DO(pcef_sess_state_store(session, state), goto cleanup);
		return;
	}
	state->used_total_octets++;
	if (strcmp(update_type, CMD_UPDATE_INPUT) == 0) {
		state->used_input_octets++;
		LOG_N("Updated used input octets. [%"PRIu64"->%"PRIu64"]", state->used_input_octets - 1, state->used_input_octets);
	} else {
		state->used_output_octets++;
		LOG_N("Updated used output octets. [%"PRIu64"->%"PRIu64"]", state->used_output_octets - 1, state->used_output_octets);
	}
	CHECK_FCT_DO(pcef_sess_state_store(session, state), goto cleanup);
	if (((state->total_octets_threshold > 0)  && (state->used_total_octets >= state->total_octets_threshold))
	 || ((state->input_octets_threshold > 0)  && (state->used_input_octets >= state->input_octets_threshold))
	 || ((state->output_octets_threshold > 0) && (state->used_output_octets >= state->output_octets_threshold))) {
		send_update_req();
	}

	return;

cleanup:
	pcef_sess_state_free(state);
}

static void dump()
{
	struct sess_state *state = NULL;

	CHECK_FCT_DO(pcef_sess_state_retrieve(session, &state), goto cleanup);
	LOG_N("-------------- User session state dump --------------");
	LOG_N("IMSI:                      %s", state->imsi);
	pcef_charging_rule_list_dump(&state->charging_rule_list);
	if (state->monitoring_key) {
		LOG_N("Monitoring key:            %s", state->monitoring_key);
		if (state->total_octets_threshold > 0) {
			LOG_N("  Total octets threshold:  %"PRIu64, state->total_octets_threshold);
		} else {
			LOG_N("  Total octets threshold:  -");
		}
		if (state->input_octets_threshold > 0) {
			LOG_N("  Input octets threshold:  %"PRIu64, state->input_octets_threshold);
		} else {
			LOG_N("  Input octets threshold:  -");
		}
		if (state->output_octets_threshold > 0) {
			LOG_N("  Output octets threshold: %"PRIu64, state->output_octets_threshold);
		} else {
			LOG_N("  Output octets threshold: -");
		}
	}
	LOG_N("Used total octets:         %"PRIu64, state->used_total_octets);
	LOG_N("Used input octets:         %"PRIu64, state->used_input_octets);
	LOG_N("Used output octets:        %"PRIu64, state->used_output_octets);
	LOG_N("=================== Dump complete ===================");
	CHECK_FCT_DO(pcef_sess_state_store(session, state), goto cleanup);

	return;

cleanup:
	pcef_sess_state_free(state);
}

static void reset()
{
	pcef_sess_state_fini(session);
	CHECK_FCT_DO(pcef_sess_state_init(session, pcef_config->imsi, pcef_config->default_charging_rule_name), return);
	LOG_N("Reset user session state.");
}

static void handle_signal()
{
	struct dirent **namelist;
	int n;
	int delete;
	char file[256];

	if (access(pcef_config->work_dir, F_OK)) {
		LOG_E("Configuration parameter 'work_dir' directory not found: '%s'", pcef_config->work_dir);
		return;
	} else if (access(pcef_config->work_dir, R_OK)) {
		LOG_E("Configuration parameter 'work_dir' read access denied: '%s'", pcef_config->work_dir);
		return;
	}
	n = scandir(pcef_config->work_dir, &namelist, NULL, alphasort);
	if (n < 0) {
		LOG_E("Scan directory failed. dir: '%s' error: (%d)'%s'", pcef_config->work_dir, errno, strerror(errno));
	} else if (n > 0) {
		while (n--) {
			delete = 0;
			if (strcmp(namelist[n]->d_name, CMD_INIT) == 0) {
				send_init_req();
				delete = 1;
			} else if ((strcmp(namelist[n]->d_name, CMD_UPDATE_INPUT) == 0)
				|| (strcmp(namelist[n]->d_name, CMD_UPDATE_OUTPUT) == 0)) {
				update_usage(namelist[n]->d_name);
				delete = 1;
			} else if (strcmp(namelist[n]->d_name, CMD_DUMP) == 0) {
				dump();
				delete = 1;
			} else if (strcmp(namelist[n]->d_name, CMD_RESET) == 0) {
				reset();
				delete = 1;
			}
			if (delete) {
				memset(file, 0, sizeof(file));
				snprintf(file, sizeof(file), "%s/%s", pcef_config->work_dir, namelist[n]->d_name);
				unlink(file);
			}
			free(namelist[n]);
		}
		free(namelist);
	} else {
		LOG_N("No files found. dir: '%s'", pcef_config->work_dir);
	}
}

static int advertise_app_support(application_id_t app_id, int (*cb)(struct msg **, struct avp *, struct session *, void *, enum disp_action *))
{
	struct disp_when when;
	memset(&when, 0, sizeof(when));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, APPLICATION_BY_ID, &app_id, &when.app, ENOENT));
	CHECK_FCT(fd_disp_register(cb, DISP_HOW_APPID, &when, NULL, NULL));
	CHECK_FCT(fd_disp_app_support(when.app, NULL, 1, 1));
	return 0;
}

static int pcef_main(char *conffile)
{
	CHECK_FCT(pcef_dict_init());
	CHECK_FCT(pcef_conf_init(conffile));
	CHECK_FCT(pcef_sess_handler_init());

	CHECK_FCT(pcef_sess_new(&session));
	CHECK_FCT(pcef_sess_state_init(session, pcef_config->imsi, pcef_config->default_charging_rule_name));

	CHECK_FCT(fd_event_trig_regcb(pcef_config->signal, "app_pcef", handle_signal));

	CHECK_FCT(advertise_app_support(AI_GX, handle_pcef_req));

	return 0;
}

void fd_ext_fini(void) {
	pcef_sess_handler_fini();
	pcef_conf_fini();
	pcef_dict_fini();
}

EXTENSION_ENTRY("app_pcef", pcef_main, "dict_gx");
