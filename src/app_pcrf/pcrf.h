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

#ifndef PCRF_H_
#define PCRF_H_

#include <freeDiameter/extension.h>

/*
 * Constants
 */
#define AI_GX	16777238

#define CC_CREDIT_CONTROL	272

#define CC_REQUEST_TYPE_INITIAL_REQUEST		1
#define CC_REQUEST_TYPE_UPDATE_REQUEST		2
#define CC_REQUEST_TYPE_TERMINATION_REQUEST	3
#define CC_REQUEST_TYPE_EVENT_REQUEST		4

#define CC_EVENT_TRIGGER_USAGE_REPORT		33

#define CC_USAGE_MONITORING_LEVEL_SESSION_LEVEL	0

/*
 * Dictionary
 */
struct pcrf_dict {
	/* Command */
	struct dict_object	*cca_cmd;
	/* AVP */
	struct dict_object	*sess_id;
	struct dict_object	*auth_application_id;
	struct dict_object	*origin_host;
	struct dict_object	*origin_realm;
	struct dict_object	*destination_realm;
	struct dict_object	*cc_request_type;
	struct dict_object	*cc_request_number;
	struct dict_object	*event_trigger;
	struct dict_object	*usage_monitoring_information;
	struct dict_object	*monitoring_key;
	struct dict_object	*usage_monitoring_level;
	struct dict_object	*granted_service_unit;
	struct dict_object	*cc_total_octets;
	struct dict_object	*cc_input_octets;
	struct dict_object	*cc_output_octets;
	struct dict_object	*charging_rule_install;
	struct dict_object	*charging_rule_remove;
	struct dict_object	*charging_rule_name;
};

extern struct pcrf_dict *pcrf_dict;

int pcrf_dict_init();
void pcrf_dict_fini();

/*
 * Configuration
 */
struct pcrf_conf {
	char		*monitoring_key;
	char		*initial_charging_rule_name;
	char		*restricted_charging_rule_name;
	uint64_t	 total_octets_threshold;
	uint64_t	 input_octets_threshold;
	uint64_t	 output_octets_threshold;
};

extern struct pcrf_conf *pcrf_config;

int pcrf_conf_init(char *conffile);
void pcrf_conf_fini();

/* In pcrf_conf.y */
int pcrf_conf_parse(char *conffile, struct pcrf_conf *config);

/*
 * Messages
 */
int pcrf_msg_avp_value_get(struct avp *avp, union avp_value **result);
int pcrf_msg_search_avp_value_from_msg(struct msg *msg, struct dict_object *avp_model, union avp_value **result);
int pcrf_msg_search_avp_from_group_avp(struct avp *group_avp, struct dict_object *child_avp_model, struct avp **result);
int pcrf_msg_init_ans_new(struct msg **msg, union avp_value *cc_req_num);
int pcrf_msg_update_ans_new(struct msg **msg, union avp_value *cc_req_num);

#endif /* PCRF_H_ */
