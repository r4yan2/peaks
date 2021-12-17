#ifndef IMPORT_H
#define IMPORT_H

#include "DBManager.h"
#include <common/Thread_Pool.h>
#include <common/utils.h>
#include "unpacker.h"

namespace peaks{
namespace import{
    void import();
    void generate_csv(std::shared_ptr<IMPORT_DBManager> dbm, std::vector<std::string> files, boost::filesystem::path &path,  int nThreads, size_t key_per_thread, int fastimport);
    void import_csv(std::shared_ptr<IMPORT_DBManager> dbm);
}
}
#endif
