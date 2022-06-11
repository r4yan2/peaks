set(SOURCE_FILES pks.cpp db.cpp encoder.cpp mitpgpskin.cpp db_key.h content.h)

set(TEMPLATES_FOLDER ${CGI_HANDLER_DIR}/templates)
set(TEMPLATES ${TEMPLATES_FOLDER}/certificate.tmpl ${TEMPLATES_FOLDER}/index.tmpl ${TEMPLATES_FOLDER}/homepage.tmpl ${TEMPLATES_FOLDER}/vindex.tmpl ${TEMPLATES_FOLDER}/stats.tmpl)

set(CPPCMS_TMPL_CC ${BIN_DIR}/cppcms_tmpl_cc)

add_custom_command(
        OUTPUT mitpgpskin.cpp
        COMMAND ${CPPCMS_TMPL_CC} ${TEMPLATES} -o mitpgpskin.cpp
        DEPENDS ${TEMPLATES}
        )

add_library(pks ${SOURCE_FILES})
