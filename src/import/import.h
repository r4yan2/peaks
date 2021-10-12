#ifndef IMPORT_H
#define IMPORT_H

#include "DBManager.h"
#include <common/Thread_Pool.h>
#include <common/utils.h>
#include "unpacker.h"

namespace peaks{
namespace import{
class Importer{
    private:
        std::shared_ptr<IMPORT_DBManager> dbm;
    public:
        Importer();
        ~Importer();
        /** peaks import starter 
         * @param vm variable map which contains boot options
         */
        void import();
        void generate_csv(std::vector<std::string> files, boost::filesystem::path &path, unsigned int nThreads, unsigned int key_per_thread, int fastimport);
        void import_csv(unsigned int nTHreads, int);
        /** helper to remove content of given directory
         * @param foldername folder to clean
         */
        void remove_directory_content(const std::string &foldername);
};

}
}
#endif
