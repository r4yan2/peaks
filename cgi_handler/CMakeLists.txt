set(SOURCE_FILES pks.cc db.cc utils.cc encoder/encoder.cc mitpgpskin.cc PacketReader.cc db_key.h content.h)

set(TEMPLATES_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/templates)
set(TEMPLATES ${TEMPLATES_FOLDER}/certificate.tmpl ${TEMPLATES_FOLDER}/index.tmpl ${TEMPLATES_FOLDER}/homepage.tmpl ${TEMPLATES_FOLDER}/vindex.tmpl)

set(CPPCMS_TMPL_CC ${CPPCMS_DIR}/bin/cppcms_tmpl_cc)

add_custom_command(
        OUTPUT mitpgpskin.cc
        COMMAND ${CPPCMS_TMPL_CC} ${TEMPLATES} -o mitpgpskin.cc
        DEPENDS ${TEMPLATES}
        )

add_library(pks ${SOURCE_FILES})
