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

struct pcrf_conf *pcrf_config = NULL;

static int validate_pcrf_conf()
{
	if ((pcrf_config->monitoring_key == NULL) || (strlen(pcrf_config->monitoring_key) == 0)) {
		LOG_E("monitoring_key is required.");
		return EINVAL;
	}
	if ((pcrf_config->initial_charging_rule_name == NULL) || (strlen(pcrf_config->initial_charging_rule_name) == 0)) {
		LOG_E("initial_charging_rule_name is required.");
		return EINVAL;
	}
	if ((pcrf_config->restricted_charging_rule_name == NULL) || (strlen(pcrf_config->restricted_charging_rule_name) == 0)) {
		LOG_E("restricted_charging_rule_name is required.");
		return EINVAL;
	}
	if ((pcrf_config->total_octets_threshold == 0)
	 && (pcrf_config->input_octets_threshold == 0)
	 && (pcrf_config->output_octets_threshold == 0)) {
		LOG_E("total_octets_threshold or input_octets_threshold or output_octets_threshold must be specified.");
		return EINVAL;
	}
	return 0;
}

int pcrf_conf_init(char *conffile)
{
	CHECK_MALLOC(pcrf_config = malloc(sizeof(struct pcrf_conf)));
	memset(pcrf_config, 0, sizeof(struct pcrf_conf));
	CHECK_FCT(pcrf_conf_parse(conffile, pcrf_config));
	CHECK_FCT(validate_pcrf_conf());
	return 0;
}

void pcrf_conf_fini()
{
	if (pcrf_config == NULL) {
		return;
	}
	free(pcrf_config->monitoring_key);
	free(pcrf_config->initial_charging_rule_name);
	free(pcrf_config->restricted_charging_rule_name);
	free(pcrf_config);
}
