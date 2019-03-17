#ifndef IMPORT_CONFIG_H
#define IMPORT_CONFIG_H
#include <string>

struct Import_DBConfig{
    std::string db_host;
    std::string db_user;
    std::string db_password;
    std::string db_database;
    std::string csv_folder;
    std::string error_folder;
};

struct Import_settings{
    std::string csv_folder;
    std::string error_folder;

};

#endif
