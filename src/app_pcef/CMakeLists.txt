PROJECT("3GPP PCEF Application" C)

BISON_FILE(pcef_conf.y)
FLEX_FILE(pcef_conf.l)
SET_SOURCE_FILES_PROPERTIES(lex.pcef_conf.c pcef_conf.tab.c PROPERTIES COMPILE_FLAGS "-I ${CMAKE_CURRENT_SOURCE_DIR}")
SET(APP_PCEF_SRC
	pcef_charging_rule.c
	pcef_configuration.c
	pcef_dictionary.c
	pcef_messages.c
	pcef_session.c
	pcef.c
	pcef.h
)
SET(APP_PCEF_SRC_GEN
	lex.pcef_conf.c
	pcef_conf.tab.c
	pcef_conf.tab.h
)

FD_ADD_EXTENSION(app_pcef ${APP_PCEF_SRC} ${APP_PCEF_SRC_GEN})

INSTALL(TARGETS app_pcef
	LIBRARY DESTINATION ${INSTALL_EXTENSIONS_SUFFIX}
	COMPONENT 3gpp-pcef-application)
