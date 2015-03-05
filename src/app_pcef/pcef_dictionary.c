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

struct pcef_dict *pcef_dict = NULL;

int pcef_dict_init()
{
	CHECK_MALLOC(pcef_dict = malloc(sizeof(struct pcef_dict)));
	memset(pcef_dict, 0, sizeof(struct pcef_dict));
	/* Command */
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "CC-Request", &pcef_dict->ccr_cmd, ENOENT));
	/* AVP */
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Session-Id", &pcef_dict->sess_id, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Auth-Application-Id", &pcef_dict->auth_application_id, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Host", &pcef_dict->origin_host, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Realm", &pcef_dict->origin_realm, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Destination-Realm", &pcef_dict->destination_realm, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "CC-Request-Type", &pcef_dict->cc_request_type, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "CC-Request-Number", &pcef_dict->cc_request_number, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Event-Trigger", &pcef_dict->event_trigger, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Usage-Monitoring-Information", &pcef_dict->usage_monitoring_information, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Monitoring-Key", &pcef_dict->monitoring_key, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Granted-Service-Unit", &pcef_dict->granted_service_unit, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Used-Service-Unit", &pcef_dict->used_service_unit, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Total-Octets", &pcef_dict->cc_total_octets, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Input-Octets", &pcef_dict->cc_input_octets, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Output-Octets", &pcef_dict->cc_output_octets, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Charging-Rule-Install", &pcef_dict->charging_rule_install, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Charging-Rule-Remove", &pcef_dict->charging_rule_remove, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Charging-Rule-Name", &pcef_dict->charging_rule_name, ENOENT));

	return 0;
}

void pcef_dict_fini()
{
	if (pcef_dict) {
		free(pcef_dict);
	}
}
