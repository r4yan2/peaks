#ifndef IMPORT_KEY_TOOLS_H
#define IMPORT_KEY_TOOLS_H

#include <Key.h>
#include <common/DBStruct.h>

using namespace peaks::common;

namespace peaks{
namespace import{
namespace Key_Tools {

    OpenPGP::Key::pkey readPkey(const OpenPGP::Key::Ptr &k, DBStruct::Unpacker_errors &modified);
    void makePKMeaningful(OpenPGP::Key::pkey &pk, DBStruct::Unpacker_errors &modified);

};

}
}

#endif //UNPACKER_KEY_TOOLS_H
