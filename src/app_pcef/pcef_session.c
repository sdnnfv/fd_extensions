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

struct session_handler *pcef_sess_handler = NULL;

int pcef_sess_handler_init()
{
	CHECK_FCT(fd_sess_handler_create(&pcef_sess_handler, (void *) free, NULL, NULL));
	return 0;
}

void pcef_sess_handler_fini()
{
	CHECK_FCT_DO(fd_sess_handler_destroy(&pcef_sess_handler, NULL), /* continue */);
}

int pcef_sess_new(struct session **result)
{
	CHECK_FCT(fd_sess_new(result, (DiamId_t) fd_g_config->cnf_diamid, strlen(fd_g_config->cnf_diamid), NULL, 0));
	return 0;
}

static int init_sess_state(struct sess_state *state, char *imsi, char *default_charging_rule_name)
{
	int rc;
	struct charging_rule *rule = NULL;

	memset(state, 0, sizeof(struct sess_state));
	state->cc_req_num = 0;
	CHECK_MALLOC_DO(state->imsi = strdup(imsi), {
		rc = ENOMEM;
		goto cleanup;
	});
	state->monitoring_key = NULL;
	fd_list_init(&state->charging_rule_list, NULL);
	CHECK_FCT_DO(rc = pcef_charging_rule_new((uint8_t *) default_charging_rule_name, strlen(default_charging_rule_name), &rule), goto cleanup);
	CHECK_FCT_DO(rc = pcef_charging_rule_add(&state->charging_rule_list, rule), goto cleanup);
	state->total_octets_threshold = 0;
	state->input_octets_threshold = 0;
	state->output_octets_threshold = 0;
	state->used_total_octets = 0;
	state->used_input_octets = 0;
	state->used_output_octets = 0;

	return 0;

cleanup:
	free(state->imsi);
	free(state->monitoring_key);
	pcef_charging_rule_free(rule);
	return rc;
}

int pcef_sess_state_init(struct session *sess, char *imsi, char *default_charging_rule_name)
{
	int rc;
	struct sess_state *state = NULL;

	CHECK_MALLOC(state = malloc(sizeof(struct sess_state)));
	init_sess_state(state, imsi, default_charging_rule_name);
	CHECK_FCT_DO(rc = pcef_sess_state_store(sess, state), {
		pcef_sess_state_free(state);
		return rc;
	});

	return 0;
}

int pcef_sess_state_retrieve(struct session *sess, struct sess_state **result)
{
	struct sess_state *state = NULL;

	CHECK_FCT(fd_sess_state_retrieve(pcef_sess_handler, sess, &state));
	if (state == NULL) {
		return ENOENT;
	}

	*result = state;

	return 0;
}

int pcef_sess_state_store(struct session *sess, struct sess_state *state)
{
	CHECK_FCT(fd_sess_state_store(pcef_sess_handler, sess, &state));
	return 0;
}

void pcef_sess_state_free(struct sess_state *state)
{
	if (state == NULL) {
		return;
	}
	free(state->imsi);
	free(state->monitoring_key);
	pcef_charging_rule_list_free(&state->charging_rule_list);
	free(state);
}

void pcef_sess_state_fini(struct session *sess)
{
	struct sess_state *state = NULL;
	CHECK_FCT_DO(pcef_sess_state_retrieve(sess, &state), return);
	pcef_sess_state_free(state);
}
