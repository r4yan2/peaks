#ifndef ANALYZER_CONFIG_H
#define ANALYZER_CONFIG_H
#include <string>

struct Analyzer_DBConfig{
    std::string db_host;
    std::string db_user;
    std::string db_password;
    std::string db_database;
    std::string analyzer_tmp_folder;
    std::string analyzer_error_folder;
    std::string analyzer_gcd_folder;
};
#endif
