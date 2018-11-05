#ifndef DUMPIMPORT_KEY_TOOLS_H
#define DUMPIMPORT_KEY_TOOLS_H

#include <Key.h>
#include "DBStruct.h"


namespace Key_Tools {

    OpenPGP::Key::pkey readPkey(const OpenPGP::Key::Ptr &k, DUMP_DBStruct::Unpacker_errors &modified);
    void makePKMeaningful(OpenPGP::Key::pkey &pk,DUMP_DBStruct::Unpacker_errors &modified);

};


#endif //UNPACKER_KEY_TOOLS_H
