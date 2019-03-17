#ifndef IMPORT_KEY_TOOLS_H
#define IMPORT_KEY_TOOLS_H

#include <Key.h>
#include "DBStruct.h"


namespace Key_Tools {

    OpenPGP::Key::pkey readPkey(const OpenPGP::Key::Ptr &k, IMPORT_DBStruct::Unpacker_errors &modified);
    void makePKMeaningful(OpenPGP::Key::pkey &pk,IMPORT_DBStruct::Unpacker_errors &modified);

};


#endif //UNPACKER_KEY_TOOLS_H
