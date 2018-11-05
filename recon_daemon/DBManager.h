#ifndef RECON_DBMANAGER_H
#define RECON_DBMANAGER_H

#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>
#include <forward_list>
#include <vector>
#include <regex>
#include "logger.h"
#include <iostream>
#include "DBStruct.h"
#include <fstream>


class RECON_DBManager {
public:
    RECON_DBManager();
    ~RECON_DBManager();

    /** recover a node from the database
     * @param key key of the node to recover
     * @return node struct corresponding to the found node
     */
    RECON_DBStruct::node get_node(const std::string key);

    /** insert node into db
     * @param n node to insert
     */
    void insert_node(const RECON_DBStruct::node &n);

    /** update node already present in db
     * @param n node to update
     */
    void update_node(const RECON_DBStruct::node &n);

    /** delete node from db
     * @param key key of the node to delete
     */
    void delete_node(const std::string key);

    /** fetch all hashes from gpg_keyserver table, used
     * to build ptree
     * @return vector of strings representing hashes
     */
    std::vector<std::string> get_all_hash();

    /** check if hash is present in db
     * @param key hash to check
     * @return bool if found, false otherwise
     */
    bool check_key(std::string key);

    /** helper to lock tables and avoid unnecessary checks during inserts
     */
    void lockTables();

    /** helper to unlock tables */
    void unlockTables();

	void write_ptree_csv(const RECON_DBStruct::node &pnode);
	void openCSVFiles();
	void insertCSV();
    
private:

	std::ofstream csv_file;
    sql::Driver *driver;
    std::shared_ptr<sql::Connection> con;
    std::shared_ptr<sql::PreparedStatement> get_pnode_stmt;
    std::shared_ptr<sql::PreparedStatement> insert_pnode_stmt;
    std::shared_ptr<sql::PreparedStatement> update_pnode_stmt;
    std::shared_ptr<sql::PreparedStatement> delete_pnode_stmt;
    std::shared_ptr<sql::PreparedStatement> get_all_hash_stmt;
    std::shared_ptr<sql::PreparedStatement> check_key_stmt;
    std::shared_ptr<sql::ResultSet> result;
	std::pair<std::string,std::string> insert_ptree_stmt;
};


#endif //PBUILD_DBMANAGER_H
