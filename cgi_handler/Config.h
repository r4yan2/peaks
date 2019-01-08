#ifndef CGI_CONFIG_H
#define CGI_CONFIG_H
#include <string>

struct Cgi_DBConfig{
    std::string db_host;
    std::string db_user;
    std::string db_password;
    std::string db_database;
};

#endif
