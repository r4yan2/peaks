#include "DBManager.h"
#include "Thread_Pool.h"
#include "utils.h"
#include "unpacker.h"


std::vector<std::string> dump_import(std::vector<std::string> keys);
std::vector<std::string> get_hashes(const std::vector<std::string> &files);
