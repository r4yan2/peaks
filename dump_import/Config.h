#ifndef DUMP_IMPORT_CONFIG_H
#define DUMP_IMPORT_CONFIG_H
#include <string>

struct Dumpimport_DBConfig{
    std::string db_host;
    std::string db_user;
    std::string db_password;
    std::string db_database;
    std::string csv_folder;
    std::string error_folder;
};

struct Dumpimport_settings{
    std::string csv_folder;
    std::string error_folder;

};

#endif
