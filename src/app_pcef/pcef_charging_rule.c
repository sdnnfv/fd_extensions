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

int pcef_charging_rule_new(uint8_t *name, size_t namelen, struct charging_rule **result)
{
	int rc;
	struct charging_rule *rule = NULL;

	CHECK_MALLOC_DO(rule = malloc(sizeof(struct charging_rule)), {
		rc = ENOMEM;
		goto cleanup;
	});
	memset(rule, 0, sizeof(struct charging_rule));
	fd_list_init(&rule->chain, rule);
	CHECK_MALLOC_DO(rule->name = (char *) os0dup(name, namelen), {
		rc = ENOMEM;
		goto cleanup;
	});
	*result = rule;

	return 0;

cleanup:
	pcef_charging_rule_free(rule);
	return rc;
}

int pcef_charging_rule_add(struct fd_list *list, struct charging_rule *rule)
{
	struct fd_list *li = NULL;
	for (li = list->next; li != list; li = li->next) {
		struct charging_rule *r = li->o;
		if (strcmp(rule->name, r->name) == 0) {
			fd_list_unlink(&r->chain);
			pcef_charging_rule_free(r);
			break;
		}
	}
	fd_list_insert_before(list, &rule->chain);
	return 0;
}

int pcef_charging_rule_remove(struct fd_list *list, struct charging_rule *rule)
{
	struct fd_list *li = NULL;
	for (li = list->next; li != list; li = li->next) {
		struct charging_rule *r = li->o;
		if (strcmp(rule->name, r->name) == 0) {
			fd_list_unlink(&r->chain);
			pcef_charging_rule_free(r);
			break;
		}
	}
	return 0;
}

void pcef_charging_rule_dump(struct charging_rule *rule)
{
	LOG_N("Charging rule name:        %s", rule->name);
}

void pcef_charging_rule_list_dump(struct fd_list *list)
{
	struct fd_list *li = NULL;
	for (li = list->next; li != list; li = li->next) {
		struct charging_rule *r = li->o;
		pcef_charging_rule_dump(r);
	}
}

void pcef_charging_rule_free(struct charging_rule *rule)
{
	if (rule == NULL) {
		return;
	}
	free(rule->name);
	free(rule);
}

void pcef_charging_rule_list_free(struct fd_list *list)
{
	if (list == NULL) {
		return;
	}
	while (!FD_IS_LIST_EMPTY(list)) {
		struct charging_rule *r = (struct charging_rule *) list->next->o;
		fd_list_unlink(&r->chain);
		pcef_charging_rule_free(r);
	}
}
