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

struct pcrf_dict *pcrf_dict = NULL;

int pcrf_dict_init()
{
	CHECK_MALLOC(pcrf_dict = malloc(sizeof(struct pcrf_dict)));
	memset(pcrf_dict, 0, sizeof(struct pcrf_dict));
	/* Command */
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "CC-Answer", &pcrf_dict->cca_cmd, ENOENT));
	/* AVP */
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Session-Id", &pcrf_dict->sess_id, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Auth-Application-Id", &pcrf_dict->auth_application_id, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Host", &pcrf_dict->origin_host, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Realm", &pcrf_dict->origin_realm, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Destination-Realm", &pcrf_dict->destination_realm, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "CC-Request-Type", &pcrf_dict->cc_request_type, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "CC-Request-Number", &pcrf_dict->cc_request_number, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Event-Trigger", &pcrf_dict->event_trigger, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Usage-Monitoring-Information", &pcrf_dict->usage_monitoring_information, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Monitoring-Key", &pcrf_dict->monitoring_key, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Usage-Monitoring-Level", &pcrf_dict->usage_monitoring_level, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Granted-Service-Unit", &pcrf_dict->granted_service_unit, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Total-Octets", &pcrf_dict->cc_total_octets, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Input-Octets", &pcrf_dict->cc_input_octets, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Output-Octets", &pcrf_dict->cc_output_octets, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Charging-Rule-Install", &pcrf_dict->charging_rule_install, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Charging-Rule-Remove", &pcrf_dict->charging_rule_remove, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Charging-Rule-Name", &pcrf_dict->charging_rule_name, ENOENT));

	return 0;
}

void pcrf_dict_fini()
{
	if (pcrf_dict) {
		free(pcrf_dict);
	}
}
