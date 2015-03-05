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

%parse-param {char *conffile}
%parse-param {struct pcef_conf *config}

%locations
%pure-parser

%{
#include <errno.h>
#include <string.h>

#include "pcef.h"
#include "pcef_conf.tab.h"

int yyparse(char *conffile, struct pcef_conf *config);
int pcef_conflex(YYSTYPE *lvalp, YYLTYPE *llocp);

int pcef_conf_parse(char *conffile, struct pcef_conf *config)
{
	extern FILE *pcef_confin;
	int ret;

	LOG_D("Parsing configuration file: %s...", conffile);
	pcef_confin = fopen(conffile, "r");
	if (pcef_confin == NULL) {
		ret = errno;
		LOG_E("Unable to open extension configuration file %s for reading: %s", conffile, strerror(ret));
		return ret;
	}
	ret = yyparse(conffile, config);
	fclose(pcef_confin);
	if (ret != 0) {
		LOG_E("Unable to parse the configuration file: %s", conffile);
		return EINVAL;
	}
	return 0;
}

void yyerror(YYLTYPE *ploc, char *conffile, struct pcef_conf *config, char const *s)
{
	LOG_E("Error in configuration parsing");
	if (ploc->first_line != ploc->last_line) {
		LOG_E("%s:%d.%d-%d.%d : %s", conffile, ploc->first_line, ploc->first_column, ploc->last_line, ploc->last_column, s);
	} else if (ploc->first_column != ploc->last_column) {
		LOG_E("%s:%d.%d-%d : %s", conffile, ploc->first_line, ploc->first_column, ploc->last_column, s);
	} else {
		LOG_E("%s:%d.%d : %s", conffile, ploc->first_line, ploc->first_column, s);
	}
}
%}

%union {
	char	*string;
	int	 integer;
}

%token <string>		QSTRING
%token <integer>	INTEGER

%token SIGNAL
%token WORK_DIR
%token DESTINATION_REALM
%token IMSI
%token DEFAULT_CHARGING_RULE_NAME

%token LEX_ERROR

%%

conffile:
	| conffile signal
	| conffile work_dir
	| conffile destination_realm
	| conffile imsi
	| conffile default_charging_rule_name
	| conffile errors
	{
		yyerror(&yylloc, conffile, config, "An error occurred while parsing the configuration file.");
		return EINVAL;
	}
	;

signal: SIGNAL '=' INTEGER ';'	{
		config->signal = $3;
	}
	;

work_dir: WORK_DIR '=' QSTRING ';'	{
		config->work_dir = $3;
	}
	;

destination_realm: DESTINATION_REALM '=' QSTRING ';'	{
		config->destination_realm = $3;
	}
	;

imsi: IMSI '=' QSTRING ';'	{
		config->imsi = $3;
	}
	;

default_charging_rule_name: DEFAULT_CHARGING_RULE_NAME '=' QSTRING ';'	{
		config->default_charging_rule_name = $3;
	}
	;

errors:	LEX_ERROR
	| error
	;
