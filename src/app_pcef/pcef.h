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

#ifndef PCEF_H_
#define PCEF_H_

#include <freeDiameter/extension.h>

/*
 * Constants
 */
#define AI_GX	16777238

#define CC_REQUEST_TYPE_INITIAL_REQUEST		1
#define CC_REQUEST_TYPE_UPDATE_REQUEST		2
#define CC_REQUEST_TYPE_TERMINATION_REQUEST	3
#define CC_REQUEST_TYPE_EVENT_REQUEST		4

#define CC_EVENT_TRIGGER_USAGE_REPORT		33

#define CMD_INIT		"init"
#define CMD_UPDATE_INPUT	"update-input"
#define CMD_UPDATE_OUTPUT	"update-output"
#define CMD_DUMP		"dump"
#define CMD_RESET		"reset"

/*
 * Dictionary
 */
struct pcef_dict {
	/* Command */
	struct dict_object	*ccr_cmd;
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
	struct dict_object	*granted_service_unit;
	struct dict_object	*used_service_unit;
	struct dict_object	*cc_total_octets;
	struct dict_object	*cc_input_octets;
	struct dict_object	*cc_output_octets;
	struct dict_object	*charging_rule_install;
	struct dict_object	*charging_rule_remove;
	struct dict_object	*charging_rule_name;
};

extern struct pcef_dict *pcef_dict;

int pcef_dict_init();
void pcef_dict_fini();

/*
 * Configuration
 */
struct pcef_conf {
	int	 signal;
	char	*work_dir;
	char	*destination_realm;
	char	*imsi;
	char	*default_charging_rule_name;
};

extern struct pcef_conf *pcef_config;

int pcef_conf_init(char *conffile);
void pcef_conf_fini();

/* In pcef_conf.y */
int pcef_conf_parse(char *conffile, struct pcef_conf *config);

/*
 * Charging Rule
 */
struct charging_rule {
	struct fd_list	 chain;
	char		*name;
};

int pcef_charging_rule_new(uint8_t *name, size_t namelen, struct charging_rule **result);
int pcef_charging_rule_add(struct fd_list *list, struct charging_rule *rule);
int pcef_charging_rule_remove(struct fd_list *list, struct charging_rule *rule);
void pcef_charging_rule_dump(struct charging_rule *rule);
void pcef_charging_rule_list_dump(struct fd_list *list);
void pcef_charging_rule_free(struct charging_rule *rule);
void pcef_charging_rule_list_free(struct fd_list *list);

/*
 * Session
 */
struct sess_state {
	uint32_t	 cc_req_num;
	char		*imsi;
	char		*monitoring_key;
	struct fd_list	 charging_rule_list;
	uint64_t	 total_octets_threshold;
	uint64_t	 input_octets_threshold;
	uint64_t	 output_octets_threshold;
	uint64_t	 used_total_octets;
	uint64_t	 used_input_octets;
	uint64_t	 used_output_octets;
};

extern struct session_handler *pcef_sess_handler;

int pcef_sess_handler_init();
void pcef_sess_handler_fini();
int pcef_sess_new(struct session **result);
int pcef_sess_state_init(struct session *sess, char *imsi, char *default_charging_rule_name);
int pcef_sess_state_retrieve(struct session *sess, struct sess_state **result);
int pcef_sess_state_store(struct session *sess, struct sess_state *state);
void pcef_sess_state_free(struct sess_state *state);

/*
 * Messages
 */
int pcef_msg_avp_value_get(struct avp *avp, union avp_value **result);
int pcef_msg_search_avp_value_from_msg(struct msg *msg, struct dict_object *avp_model, union avp_value **result);
int pcef_msg_search_avp_from_group_avp(struct avp *group_avp, struct dict_object *child_avp_model, struct avp **result);
int pcef_msg_init_req_new(struct session *sess, struct msg **result);
int pcef_msg_update_req_new(struct session *sess, struct msg **result);

#endif /* PCEF_H_ */
