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

#include "pcrf.h"

static int set_common_ans_avp(struct msg *ans, int cc_req_type, union avp_value *cc_req_num)
{
	int rc;
	struct avp *avp = NULL;
	union avp_value val;

	/* Auth-Application-Id */
	avp = NULL;
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->auth_application_id, 0, &avp), goto cleanup);
	val.u32 = AI_GX;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	/* Origin-Host */
	avp = NULL;
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->origin_host, 0, &avp), goto cleanup);
	val.os.data = (uint8_t *) fd_g_config->cnf_diamid;
	val.os.len = fd_g_config->cnf_diamid_len;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	/* Origin-Realm */
	avp = NULL;
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->origin_realm, 0, &avp), goto cleanup);
	val.os.data = (uint8_t *) fd_g_config->cnf_diamrlm;
	val.os.len = fd_g_config->cnf_diamrlm_len;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	/* CC-Request-Type */
	avp = NULL;
	memset(&val, 0, sizeof(val));
	CHECK_FCT(rc = fd_msg_avp_new(pcrf_dict->cc_request_type, 0, &avp));
	val.i32 = cc_req_type;
	CHECK_FCT(rc = fd_msg_avp_setvalue(avp, &val));
	CHECK_FCT(rc = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp));

	/* CC-Request-Number */
	avp = NULL;
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->cc_request_number, 0, &avp), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, cc_req_num), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	return 0;

cleanup:
	return rc;
}

static int set_event_trigger(struct msg *ans, int event_trigger)
{
	int rc;
	struct avp *avp = NULL;
	union avp_value val;

	/* Event-Trigger */
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->event_trigger, 0, &avp), goto cleanup);
	val.i32 = event_trigger;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);

	CHECK_FCT_DO(rc = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	return 0;

cleanup:
	if (avp) {
		fd_msg_free(avp);
	}
	return rc;
}

static int set_usage_monitoring_information(struct msg *ans, char *monitoring_key, uint64_t total_octets_threshold, uint64_t input_octets_threshold, uint64_t output_octets_threshold)
{
	int rc;
	struct avp *usage_monitoring_information_avp = NULL;
	struct avp *monitoring_key_avp = NULL;
	struct avp *usage_monitoring_level_avp = NULL;
	struct avp *granted_service_unit_avp = NULL;
	struct avp *cc_total_octets_avp = NULL;
	struct avp *cc_input_octets_avp = NULL;
	struct avp *cc_output_octets_avp = NULL;
	union avp_value val;

	/* CC-Total-Octets */
	if (total_octets_threshold > 0) {
		memset(&val, 0, sizeof(val));
		CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->cc_total_octets, 0, &cc_total_octets_avp), goto cleanup);
		val.u64 = total_octets_threshold;
		CHECK_FCT_DO(rc = fd_msg_avp_setvalue(cc_total_octets_avp, &val), goto cleanup);
	}

	/* CC-Input-Octets */
	if (input_octets_threshold > 0) {
		memset(&val, 0, sizeof(val));
		CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->cc_input_octets, 0, &cc_input_octets_avp), goto cleanup);
		val.u64 = input_octets_threshold;
		CHECK_FCT_DO(rc = fd_msg_avp_setvalue(cc_input_octets_avp, &val), goto cleanup);
	}

	/* CC-Output-Octets */
	if (output_octets_threshold > 0) {
		memset(&val, 0, sizeof(val));
		CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->cc_output_octets, 0, &cc_output_octets_avp), goto cleanup);
		val.u64 = output_octets_threshold;
		CHECK_FCT_DO(rc = fd_msg_avp_setvalue(cc_output_octets_avp, &val), goto cleanup);
	}

	/* Granted-Service-Unit */
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->granted_service_unit, 0, &granted_service_unit_avp), goto cleanup);
	if (total_octets_threshold > 0) {
		CHECK_FCT_DO(rc = fd_msg_avp_add(granted_service_unit_avp, MSG_BRW_LAST_CHILD, cc_total_octets_avp), goto cleanup);
	}
	if (input_octets_threshold > 0) {
		CHECK_FCT_DO(rc = fd_msg_avp_add(granted_service_unit_avp, MSG_BRW_LAST_CHILD, cc_input_octets_avp), goto cleanup);
	}
	if (output_octets_threshold > 0) {
		CHECK_FCT_DO(rc = fd_msg_avp_add(granted_service_unit_avp, MSG_BRW_LAST_CHILD, cc_output_octets_avp), goto cleanup);
	}

	/* Usage-Monitoring-Level */
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->usage_monitoring_level, 0, &usage_monitoring_level_avp), goto cleanup);
	val.i32 = CC_USAGE_MONITORING_LEVEL_SESSION_LEVEL;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(usage_monitoring_level_avp, &val), goto cleanup);

	/* Monitoring-Key */
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->monitoring_key, 0, &monitoring_key_avp), goto cleanup);
	val.os.data = (uint8_t *) monitoring_key;
	val.os.len = strlen(monitoring_key);
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(monitoring_key_avp, &val), goto cleanup);

	/* Usage-Monitoring-Information */
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->usage_monitoring_information, 0, &usage_monitoring_information_avp), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(usage_monitoring_information_avp, MSG_BRW_LAST_CHILD, monitoring_key_avp), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(usage_monitoring_information_avp, MSG_BRW_LAST_CHILD, usage_monitoring_level_avp), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(usage_monitoring_information_avp, MSG_BRW_LAST_CHILD, granted_service_unit_avp), goto cleanup);

	CHECK_FCT_DO(rc = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, usage_monitoring_information_avp), goto cleanup);

	return 0;

cleanup:
	if (usage_monitoring_information_avp) {
		fd_msg_free(usage_monitoring_information_avp);
	}
	if (monitoring_key_avp) {
		fd_msg_free(monitoring_key_avp);
	}
	if (usage_monitoring_level_avp) {
		fd_msg_free(usage_monitoring_level_avp);
	}
	if (granted_service_unit_avp) {
		fd_msg_free(granted_service_unit_avp);
	}
	if (cc_total_octets_avp) {
		fd_msg_free(cc_total_octets_avp);
	}
	return rc;
}

static int set_install_charging_rule(struct msg *ans, char *charging_rule_name)
{
	int rc;
	struct avp *charging_rule_install_avp = NULL;
	struct avp *charging_rule_name_avp = NULL;
	union avp_value val;

	/* Charging-Rule-Install */
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->charging_rule_install, 0, &charging_rule_install_avp), goto cleanup);

	/* Charging-Rule-Name */
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->charging_rule_name, 0, &charging_rule_name_avp), goto cleanup);
	val.os.data = (uint8_t *) charging_rule_name;
	val.os.len = strlen(charging_rule_name);
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(charging_rule_name_avp, &val), goto cleanup);

	CHECK_FCT_DO(rc = fd_msg_avp_add(charging_rule_install_avp, MSG_BRW_LAST_CHILD, charging_rule_name_avp), goto cleanup);

	CHECK_FCT_DO(rc = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, charging_rule_install_avp), goto cleanup);

	return 0;

cleanup:
	if (charging_rule_install_avp) {
		fd_msg_free(charging_rule_install_avp);
	}
	if (charging_rule_name_avp) {
		fd_msg_free(charging_rule_name_avp);
	}
	return rc;
}

static int set_remove_charging_rule(struct msg *ans, char *charging_rule_name)
{
	int rc;
	struct avp *charging_rule_remove_avp = NULL;
	struct avp *charging_rule_name_avp = NULL;
	union avp_value val;

	/* Charging-Rule-Remove */
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->charging_rule_remove, 0, &charging_rule_remove_avp), goto cleanup);

	/* Charging-Rule-Name */
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcrf_dict->charging_rule_name, 0, &charging_rule_name_avp), goto cleanup);
	val.os.data = (uint8_t *) charging_rule_name;
	val.os.len = strlen(charging_rule_name);
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(charging_rule_name_avp, &val), goto cleanup);

	CHECK_FCT_DO(rc = fd_msg_avp_add(charging_rule_remove_avp, MSG_BRW_LAST_CHILD, charging_rule_name_avp), goto cleanup);

	CHECK_FCT_DO(rc = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, charging_rule_remove_avp), goto cleanup);

	return 0;

cleanup:
	if (charging_rule_remove_avp) {
		fd_msg_free(charging_rule_remove_avp);
	}
	if (charging_rule_name_avp) {
		fd_msg_free(charging_rule_name_avp);
	}
	return rc;
}

int pcrf_msg_avp_value_get(struct avp *avp, union avp_value **result)
{
	struct avp_hdr *hdr = NULL;
	CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
	*result = hdr->avp_value;
	return 0;
}

int pcrf_msg_search_avp_value_from_msg(struct msg *msg, struct dict_object *avp_model, union avp_value **result)
{
	struct avp *avp = NULL;

	CHECK_FCT(fd_msg_search_avp(msg, avp_model, &avp));
	if (avp == NULL) {
		*result = NULL;
		return 0;
	}
	CHECK_FCT(pcrf_msg_avp_value_get(avp, result));
	return 0;
}

int pcrf_msg_search_avp_from_group_avp(struct avp *group_avp, struct dict_object *child_avp_model, struct avp **result)
{
	struct dict_avp_data dictdata;
	struct avp *next_child_avp = NULL;

	CHECK_FCT(fd_dict_getval(child_avp_model, &dictdata));

	CHECK_FCT(fd_msg_browse(group_avp, MSG_BRW_FIRST_CHILD, (void *) &next_child_avp, NULL));
	while (next_child_avp) {
		struct avp_hdr *hdr = NULL;
		CHECK_FCT(fd_msg_avp_hdr(next_child_avp, &hdr));
		if ((hdr->avp_code   == dictdata.avp_code)
		 && (hdr->avp_vendor == dictdata.avp_vendor)) {
			/* AVPが見つかった */
			struct dictionary *dict;
			CHECK_FCT(fd_dict_getdict(child_avp_model, &dict));
			CHECK_FCT(fd_msg_parse_dict(next_child_avp, dict, NULL));
			*result = next_child_avp;
			return 0;
		}
		CHECK_FCT(fd_msg_browse(next_child_avp, MSG_BRW_NEXT, &next_child_avp, NULL));
	}
	/* AVPが見つからなかった */
	*result = NULL;
	return 0;
}

int pcrf_msg_init_ans_new(struct msg **msg, union avp_value *cc_req_num)
{
	int rc;

	CHECK_FCT_DO(rc = fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0), goto cleanup);
	CHECK_FCT_DO(rc = set_common_ans_avp(*msg, CC_REQUEST_TYPE_INITIAL_REQUEST, cc_req_num), goto cleanup);
	CHECK_FCT_DO(rc = set_event_trigger(*msg, CC_EVENT_TRIGGER_USAGE_REPORT), goto cleanup);
	CHECK_FCT_DO(rc = set_usage_monitoring_information(*msg, pcrf_config->monitoring_key, pcrf_config->total_octets_threshold, pcrf_config->input_octets_threshold, pcrf_config->output_octets_threshold), goto cleanup);
	CHECK_FCT_DO(rc = set_install_charging_rule(*msg, pcrf_config->initial_charging_rule_name), goto cleanup);

	return 0;

cleanup:
	return rc;
}

int pcrf_msg_update_ans_new(struct msg **msg, union avp_value *cc_req_num)
{
	int rc;

	CHECK_FCT_DO(rc = fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0), goto cleanup);
	CHECK_FCT_DO(rc = set_common_ans_avp(*msg, CC_REQUEST_TYPE_UPDATE_REQUEST, cc_req_num), goto cleanup);
	CHECK_FCT_DO(rc = set_remove_charging_rule(*msg, pcrf_config->initial_charging_rule_name), goto cleanup);
	CHECK_FCT_DO(rc = set_install_charging_rule(*msg, pcrf_config->restricted_charging_rule_name), goto cleanup);

	return 0;

cleanup:
	return rc;
}
