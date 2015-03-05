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

#include "pcef.h"

static int set_common_req_avp(struct msg *req, struct session *sess, int cc_req_type)
{
	int rc;
	struct avp *avp = NULL;
	union avp_value val;
	struct sess_state *state = NULL;

	/* Session-Id */
	avp = NULL;
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->sess_id, 0, &avp), goto cleanup);
	CHECK_FCT_DO(rc = fd_sess_getsid(sess, &val.os.data, &val.os.len), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	/* Auth-Application-Id */
	avp = NULL;
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->auth_application_id, 0, &avp), goto cleanup);
	val.u32 = AI_GX;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	/* Origin-Host */
	avp = NULL;
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->origin_host, 0, &avp), goto cleanup);
	val.os.data = (uint8_t *) fd_g_config->cnf_diamid;
	val.os.len = fd_g_config->cnf_diamid_len;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	/* Origin-Realm */
	avp = NULL;
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->origin_realm, 0, &avp), goto cleanup);
	val.os.data = (uint8_t *) fd_g_config->cnf_diamrlm;
	val.os.len = fd_g_config->cnf_diamrlm_len;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	/* Destination-Realm */
	avp = NULL;
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->destination_realm, 0, &avp), goto cleanup);
	val.os.data = (uint8_t *) pcef_config->destination_realm;
	val.os.len = strlen(pcef_config->destination_realm);
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	/* CC-Request-Type */
	avp = NULL;
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->cc_request_type, 0, &avp), goto cleanup);
	val.i32 = cc_req_type;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	/* CC-Request-Number */
	avp = NULL;
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->cc_request_number, 0, &avp), goto cleanup);
	CHECK_FCT_DO(pcef_sess_state_retrieve(sess, &state), goto cleanup);
	switch (cc_req_type) {
	case CC_REQUEST_TYPE_INITIAL_REQUEST:
	case CC_REQUEST_TYPE_EVENT_REQUEST:
		state->cc_req_num = 0;
		break;
	case CC_REQUEST_TYPE_UPDATE_REQUEST:
	case CC_REQUEST_TYPE_TERMINATION_REQUEST:
		state->cc_req_num++;
		break;
	default:
		ASSERT(0);
	}
	val.u32 = state->cc_req_num;
	CHECK_FCT_DO(rc = pcef_sess_state_store(sess, state), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	return 0;

cleanup:
	return rc;
}

static int set_event_trigger(struct msg *msg, int event_trigger)
{
	int rc;
	struct avp *avp = NULL;
	union avp_value val;

	/* Event-Trigger */
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->event_trigger, 0, &avp), goto cleanup);
	val.i32 = event_trigger;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(avp, &val), goto cleanup);

	CHECK_FCT_DO(rc = fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp), goto cleanup);

	return 0;

cleanup:
	if (avp) {
		fd_msg_free(avp);
	}
	return rc;
}

static int set_usage_monitoring_information(struct msg *msg, struct session *sess)
{
	int rc;
	struct avp *usage_monitoring_information_avp = NULL;
	struct avp *used_service_avp = NULL;
	struct avp *cc_total_octets_avp = NULL;
	struct avp *cc_input_octets_avp = NULL;
	struct avp *cc_output_octets_avp = NULL;
	union avp_value val;
	struct sess_state *state = NULL;

	CHECK_FCT_DO(pcef_sess_state_retrieve(sess, &state), goto cleanup);

	/* CC-Total-Octets */
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->cc_total_octets, 0, &cc_total_octets_avp), goto cleanup);
	val.u64 = state->used_total_octets;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(cc_total_octets_avp, &val), goto cleanup);

	/* CC-Input-Octets */
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->cc_input_octets, 0, &cc_input_octets_avp), goto cleanup);
	val.u64 = state->used_input_octets;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(cc_input_octets_avp, &val), goto cleanup);

	/* CC-Output-Octets */
	memset(&val, 0, sizeof(val));
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->cc_output_octets, 0, &cc_output_octets_avp), goto cleanup);
	val.u64 = state->used_output_octets;
	CHECK_FCT_DO(rc = fd_msg_avp_setvalue(cc_output_octets_avp, &val), goto cleanup);

	/* Used-Service-Unit */
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->used_service_unit, 0, &used_service_avp), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(used_service_avp, MSG_BRW_LAST_CHILD, cc_total_octets_avp), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(used_service_avp, MSG_BRW_LAST_CHILD, cc_input_octets_avp), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(used_service_avp, MSG_BRW_LAST_CHILD, cc_output_octets_avp), goto cleanup);

	/* Usage-Monitoring-Information */
	CHECK_FCT_DO(rc = fd_msg_avp_new(pcef_dict->usage_monitoring_information, 0, &usage_monitoring_information_avp), goto cleanup);
	CHECK_FCT_DO(rc = fd_msg_avp_add(usage_monitoring_information_avp, MSG_BRW_LAST_CHILD, used_service_avp), goto cleanup);

	CHECK_FCT_DO(rc = fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, usage_monitoring_information_avp), goto cleanup);

	CHECK_FCT_DO(pcef_sess_state_store(sess, state), goto cleanup);

	return 0;

cleanup:
	if (usage_monitoring_information_avp) {
		fd_msg_free(usage_monitoring_information_avp);
	}
	if (used_service_avp) {
		fd_msg_free(used_service_avp);
	}
	if (cc_total_octets_avp) {
		fd_msg_free(cc_total_octets_avp);
	}
	if (state) {
		pcef_sess_state_free(state);
	}
	return rc;
}

int pcef_msg_avp_value_get(struct avp *avp, union avp_value **result)
{
	struct avp_hdr *hdr = NULL;
	CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
	*result = hdr->avp_value;
	return 0;
}

int pcef_msg_search_avp_value_from_msg(struct msg *msg, struct dict_object *avp_model, union avp_value **result)
{
	struct avp *avp = NULL;

	CHECK_FCT(fd_msg_search_avp(msg, avp_model, &avp));
	if (avp == NULL) {
		*result = NULL;
		return 0;
	}
	CHECK_FCT(pcef_msg_avp_value_get(avp, result));
	return 0;
}

int pcef_msg_search_avp_from_group_avp(struct avp *group_avp, struct dict_object *child_avp_model, struct avp **result)
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

int pcef_msg_init_req_new(struct session *sess, struct msg **result)
{
	int rc;
	struct msg *req = NULL;

	CHECK_FCT_DO(rc = fd_msg_new(pcef_dict->ccr_cmd, MSGFL_ALLOC_ETEID, &req), goto cleanup);
	CHECK_FCT_DO(rc = set_common_req_avp(req, sess, CC_REQUEST_TYPE_INITIAL_REQUEST), goto cleanup);

	*result = req;

	return 0;

cleanup:
	if (req) {
		fd_msg_free(req);
	}
	return rc;
}

int pcef_msg_update_req_new(struct session *sess, struct msg **result)
{
	int rc;
	struct msg *req = NULL;

	CHECK_FCT_DO(rc = fd_msg_new(pcef_dict->ccr_cmd, MSGFL_ALLOC_ETEID, &req), goto cleanup);
	CHECK_FCT_DO(rc = set_common_req_avp(req, sess, CC_REQUEST_TYPE_UPDATE_REQUEST), goto cleanup);
	CHECK_FCT_DO(rc = set_event_trigger(req, CC_EVENT_TRIGGER_USAGE_REPORT), goto cleanup);
	CHECK_FCT_DO(rc = set_usage_monitoring_information(req, sess), goto cleanup);

	*result = req;

	return 0;

cleanup:
	if (req) {
		fd_msg_free(req);
	}
	return rc;
}
