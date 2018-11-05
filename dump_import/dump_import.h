#ifndef DUMP_IMPORT_H
#define DUMP_IMPORT_H

#include "DBManager.h"
#include "Thread_Pool.h"
#include "utils.h"
#include "unpacker.h"

/** dump import from a string of keys (useful for reconing)
 * @param keys vector of keys as strings
 * @return vector of hashes of processed keys
 */
std::vector<std::string> dump_import(std::vector<std::string> keys);

/** get hashes from processed keys
 * @param files to know from which file fetch the key
 * @return vector of strings which contains the hashes
 */
std::vector<std::string> get_hashes(const std::vector<std::string> &files);

/** peaks import starter 
 * @param vm variable map which contains boot options
 */
void import(po::variables_map &vm);
void generate_csv(std::vector<std::string> files, boost::filesystem::path &path, unsigned int nThreads, unsigned int key_per_thread, int fastimport);
void import_csv(std::shared_ptr<DUMPIMPORT_DBManager> dbm, int fastimport);
/** helper to remove content of given directory
 * @param foldername folder to clean
 */
void remove_directory_content(const std::string &foldername);


#endif
