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

#endif
