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
        DBSettings db_settings;
        std::shared_ptr<IMPORT_DBManager> dbm;
    public:
        Importer();
        ~Importer();
        /** peaks import starter 
         * @param vm variable map which contains boot options
         */
        void import();
        void generate_csv(std::vector<std::string> files, boost::filesystem::path &path, unsigned int nThreads, unsigned int key_per_thread, int fastimport);
        void import_csv(unsigned int nTHreads, int fastimport);
        /** helper to remove content of given directory
         * @param foldername folder to clean
         */
        void remove_directory_content(const std::string &foldername);
};

class ReconImporter{
    private:
        bool unpack;
        DBSettings db_settings;
    public:

        ReconImporter(po::variables_map &vm);
        ReconImporter();
        ~ReconImporter();

        /** Import certificates from a string of keys (useful for reconing)
         * @param keys vector of keys as strings
         * @return vector of hashes of processed keys
         */
        std::vector<std::string> import(std::vector<std::string> keys);
        
        /** get hashes from processed keys
         * @param files to know from which file fetch the key
         * @return vector of strings which contains the hashes
         */
        std::vector<std::string> get_hashes(const std::vector<std::string> &files);

};

}
}
#endif
