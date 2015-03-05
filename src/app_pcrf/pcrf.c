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

static int handle_cc_init_req(struct msg **msg, union avp_value *cc_req_num)
{
	LOG_N("Received initial request.");
	CHECK_FCT(pcrf_msg_init_ans_new(msg, cc_req_num));
	LOG_N("Sending initial answer...");

	return 0;
}

static int handle_cc_update_req(struct msg **msg, union avp_value *cc_req_num)
{
	LOG_N("Received update request.");
	CHECK_FCT(pcrf_msg_update_ans_new(msg, cc_req_num));
	LOG_N("Sending update answer...");

	return 0;
}

static int handle_cc_req(struct msg **msg)
{
	union avp_value *cc_req_type = NULL;
	union avp_value *cc_req_num = NULL;

	CHECK_FCT(pcrf_msg_search_avp_value_from_msg(*msg, pcrf_dict->cc_request_type, &cc_req_type));
	if (cc_req_type == NULL) {
		LOG_E("cc_request_type is required.");
		return EINVAL;
	}
	CHECK_FCT(pcrf_msg_search_avp_value_from_msg(*msg, pcrf_dict->cc_request_number, &cc_req_num));
	if (cc_req_num == NULL) {
		LOG_E("cc_request_number is required.");
		return EINVAL;
	}

	switch (cc_req_type->i32) {
	case CC_REQUEST_TYPE_INITIAL_REQUEST:
		CHECK_FCT(handle_cc_init_req(msg, cc_req_num));
		break;
	case CC_REQUEST_TYPE_UPDATE_REQUEST:
		CHECK_FCT(handle_cc_update_req(msg, cc_req_num));
		break;
	case CC_REQUEST_TYPE_TERMINATION_REQUEST:
	case CC_REQUEST_TYPE_EVENT_REQUEST:
		// TODO
		break;
	default:
		// TODO
		break;
	}
	return 0;
}

static int get_cmd_code(struct msg *msg, command_code_t *result)
{
	struct msg_hdr *msg_hdr = NULL;
	CHECK_FCT(fd_msg_hdr(msg, &msg_hdr));
	*result = msg_hdr->msg_code;
	return 0;
}

static int handle_pcrf_req(struct msg **msg, struct avp *avp, struct session *sess, void *opaque, enum disp_action *act)
{
	command_code_t cmd_code;
	CHECK_FCT(get_cmd_code(*msg, &cmd_code));
	switch (cmd_code) {
	case CC_CREDIT_CONTROL:
		CHECK_FCT(handle_cc_req(msg));
		break;
	default:
		CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0));
		CHECK_FCT(fd_msg_rescode_set(*msg, "DIAMETER_COMMAND_UNSUPPORTED", NULL, NULL, 1));
		break;
	}
	*act = DISP_ACT_SEND;
	return 0;
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

static int pcrf_main(char *conffile)
{
	CHECK_FCT(pcrf_dict_init());
	CHECK_FCT(pcrf_conf_init(conffile));

	CHECK_FCT(advertise_app_support(AI_GX, handle_pcrf_req));

	return 0;
}

void fd_ext_fini(void) {
	pcrf_conf_fini();
	pcrf_dict_fini();
}

EXTENSION_ENTRY("app_pcrf", pcrf_main, "dict_gx");
