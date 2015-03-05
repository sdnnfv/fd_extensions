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

struct pcef_conf *pcef_config = NULL;

static int validate_pcef_conf()
{
	if ((pcef_config->destination_realm == NULL) || (strlen(pcef_config->destination_realm) == 0)) {
		LOG_E("destination_realm is required.");
		return EINVAL;
	}
	if ((pcef_config->imsi == NULL) || (strlen(pcef_config->imsi) == 0)) {
		LOG_E("imsi is required.");
		return EINVAL;
	}
	if ((pcef_config->default_charging_rule_name == NULL) || (strlen(pcef_config->default_charging_rule_name) == 0)) {
		LOG_E("default_charging_rule_name is required.");
		return EINVAL;
	}
	return 0;
}

int pcef_conf_init(char *conffile)
{
	CHECK_MALLOC(pcef_config = malloc(sizeof(struct pcef_conf)));
	memset(pcef_config, 0, sizeof(struct pcef_conf));
	CHECK_FCT(pcef_conf_parse(conffile, pcef_config));
	CHECK_FCT(validate_pcef_conf());
	return 0;
}

void pcef_conf_fini()
{
	if (pcef_config == NULL) {
		return;
	}
	free(pcef_config->destination_realm);
	free(pcef_config->imsi);
	free(pcef_config->default_charging_rule_name);
	free(pcef_config);
}
