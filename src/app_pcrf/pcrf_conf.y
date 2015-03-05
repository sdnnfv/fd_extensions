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
%parse-param {struct pcrf_conf *config}

%locations
%pure-parser

%{
#include <errno.h>
#include <string.h>

#include "pcrf.h"
#include "pcrf_conf.tab.h"

int yyparse(char *conffile, struct pcrf_conf *config);
int pcrf_conflex(YYSTYPE *lvalp, YYLTYPE *llocp);

int pcrf_conf_parse(char *conffile, struct pcrf_conf *config)
{
	extern FILE *pcrf_confin;
	int ret;

	LOG_D("Parsing configuration file: %s...", conffile);
	pcrf_confin = fopen(conffile, "r");
	if (pcrf_confin == NULL) {
		ret = errno;
		LOG_E("Unable to open extension configuration file %s for reading: %s", conffile, strerror(ret));
		return ret;
	}
	ret = yyparse(conffile, config);
	fclose(pcrf_confin);
	if (ret != 0) {
		LOG_E("Unable to parse the configuration file: %s", conffile);
		return EINVAL;
	}
	return 0;
}

void yyerror(YYLTYPE *ploc, char *conffile, struct pcrf_conf *config, char const *s)
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

%token MONITORING_KEY
%token INITIAL_CHARGING_RULE_NAME
%token RESTRICTED_CHARGING_RULE_NAME
%token TOTAL_OCTETS_THRESHOLD
%token INPUT_OCTETS_THRESHOLD
%token OUTPUT_OCTETS_THRESHOLD

%token LEX_ERROR

%%

conffile:
	| conffile monitoring_key
	| conffile initial_charging_rule_name
	| conffile restricted_charging_rule_name
	| conffile total_octets_threshold
	| conffile input_octets_threshold
	| conffile output_octets_threshold
	| conffile errors
	{
		yyerror(&yylloc, conffile, config, "An error occurred while parsing the configuration file.");
		return EINVAL;
	}
	;

monitoring_key: MONITORING_KEY '=' QSTRING ';'	{
		config->monitoring_key = $3;
	}
	;

initial_charging_rule_name: INITIAL_CHARGING_RULE_NAME '=' QSTRING ';'	{
		config->initial_charging_rule_name = $3;
	}
	;

restricted_charging_rule_name: RESTRICTED_CHARGING_RULE_NAME '=' QSTRING ';'	{
		config->restricted_charging_rule_name = $3;
	}
	;

total_octets_threshold: TOTAL_OCTETS_THRESHOLD '=' INTEGER ';'	{
		if ($3 < 1) {
			LOG_E("total_octets_threshold must be positive");
			YYERROR;
		}
		config->total_octets_threshold = $3;
	}
	;

input_octets_threshold: INPUT_OCTETS_THRESHOLD '=' INTEGER ';'	{
		if ($3 < 1) {
			LOG_E("input_octets_threshold must be positive");
			YYERROR;
		}
		config->input_octets_threshold = $3;
	}
	;

output_octets_threshold: OUTPUT_OCTETS_THRESHOLD '=' INTEGER ';'	{
		if ($3 < 1) {
			LOG_E("output_octets_threshold must be positive");
			YYERROR;
		}
		config->output_octets_threshold = $3;
	}
	;

errors:	LEX_ERROR
	| error
	;
