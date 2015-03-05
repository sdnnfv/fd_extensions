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

%{
#include "pcef.h"
#include "pcef_conf.tab.h"

#define YY_USER_ACTION { \
	yylloc->first_column = yylloc->last_column + 1; \
	yylloc->last_column = yylloc->first_column + yyleng - 1; \
}
#define YY_NO_INPUT
%}

%option bison-bridge bison-locations
%option noyywrap
%option nounput

qstring	\"[^\"\n]*\"

%%

	/* コメントのみの行、空白文字のみの行、改行を飛ばす */
^[[:blank:]]*#.*\n	|
^[[:blank:]]*\n		|
\n	{
		yylloc->first_line++;
		yylloc->last_line++;
		yylloc->last_column = 0;
	}

	/* コメントを飛ばす */
#.*$

	/* 空白、タブを飛ばす */
[[:blank:]]+

{qstring}	{
		yylval->string = strdup(yytext + 1);
		if (!yylval->string) {
			LOG_E("Unable to copy the string '%s': %s", yytext, strerror(errno));
			return LEX_ERROR;
		}
		yylval->string[strlen(yytext) - 2] = '\0';
		return QSTRING;
	}

[[:digit:]]+	{
		int ret = sscanf(yytext, "%i", &yylval->integer);
		if (ret != 1) {
			LOG_E("Unable to convert the value '%s' to a valid number: %s", yytext, strerror(errno));
			return LEX_ERROR;
		}
		return INTEGER;
	}

"="	|
":"	|
";"		{ return yytext[0]; }

(?i:"signal")				{ return SIGNAL; }
(?i:"work_dir")				{ return WORK_DIR; }
(?i:"destination_realm")		{ return DESTINATION_REALM; }
(?i:"imsi")				{ return IMSI; }
(?i:"default_charging_rule_name")	{ return DEFAULT_CHARGING_RULE_NAME; }

.	{
		LOG_E("Unrecognized character on line %d col %d: '%c'.", yylloc->first_line, yylloc->first_column, *yytext);
		return LEX_ERROR; 
	}

%%
