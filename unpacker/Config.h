#ifndef UNPACKER_CONFIG_H
#define UNPACKER_CONFIG_H
#include <string>

struct Unpacker_DBConfig{
    std::string db_host;
    std::string db_user;
    std::string db_password;
    std::string db_database;
    std::string unpacker_tmp_folder;
    std::string unpacker_error_folder;
};

#endif
