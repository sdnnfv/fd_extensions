PROJECT("3GPP PCRF Application" C)

BISON_FILE(pcrf_conf.y)
FLEX_FILE(pcrf_conf.l)
SET_SOURCE_FILES_PROPERTIES(lex.pcrf_conf.c pcrf_conf.tab.c PROPERTIES COMPILE_FLAGS "-I ${CMAKE_CURRENT_SOURCE_DIR}")
SET(APP_PCRF_SRC
	pcrf_configuration.c
	pcrf_dictionary.c
	pcrf_messages.c
	pcrf.c
	pcrf.h
)
SET(APP_PCRF_SRC_GEN
	lex.pcrf_conf.c
	pcrf_conf.tab.c
	pcrf_conf.tab.h
)

FD_ADD_EXTENSION(app_pcrf ${APP_PCRF_SRC} ${APP_PCRF_SRC_GEN})

INSTALL(TARGETS app_pcrf
	LIBRARY DESTINATION ${INSTALL_EXTENSIONS_SUFFIX}
	COMPONENT 3gpp-pcrf-application)
