#ifndef RECON_DBMANAGER_H
#define RECON_DBMANAGER_H

#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>
#include <forward_list>
#include <vector>
#include <regex>
//#include <Key.h>
#include <iostream>
#include "DBStruct.h"

class RECON_DBManager {
public:
    RECON_DBManager();

    ~RECON_DBManager();

    DBStruct::node get_node(const std::string key);
    void insert_node(const DBStruct::node &n);
    void delete_node(const std::string key);
    std::vector<std::string> get_all_hash();
    void lockTables();
    void unlockTables();
    
private:

    sql::Driver *driver;
    std::shared_ptr<sql::Connection> con;
    std::shared_ptr<sql::PreparedStatement> get_pnode_stmt;
    std::shared_ptr<sql::PreparedStatement> insert_pnode_stmt;
    std::shared_ptr<sql::PreparedStatement> delete_pnode_stmt;
    std::shared_ptr<sql::PreparedStatement> get_all_hash_stmt;
    std::shared_ptr<sql::ResultSet> result;
};


#endif //PBUILD_DBMANAGER_H
