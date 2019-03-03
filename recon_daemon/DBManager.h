#ifndef RECON_DBMANAGER_H
#define RECON_DBMANAGER_H

#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>
#include <forward_list>
#include <vector>
#include <regex>
#include <iostream>
#include "DBStruct.h"
#include "Recon_settings.h"
#include <fstream>

/** RECON_DBManager class is responsible to
 * manage the connection to the database. The base class is 
 * a virtual one, from which the specific connector inherit
 */
class RECON_DBManager {
public:
    /** Constructor
     * @param settings Settings for the database
     */
    RECON_DBManager(const Recon_DBConfig & db_settings);

    /** Default destructor
     * */
    ~RECON_DBManager();

    virtual void init_database_connection() = 0;
    virtual RECON_DBStruct::node get_node(const std::string key) = 0;
    virtual void insert_node(const RECON_DBStruct::node &n) = 0;
    virtual void update_node(const RECON_DBStruct::node &n) = 0;
    virtual void delete_node(const std::string key) = 0;
    virtual bool check_key(const std::string key) = 0;
    virtual std::vector<std::string> fetch_removed_elements() = 0;
    virtual std::vector<std::string> get_all_hash() = 0;
    virtual void commit_memtree() = 0;
protected:
    /**
     * store the config which will be used for the actual database connection
     */
    Recon_DBConfig settings;

    /**
     * store a pointer to the csv file which will be needed to 
     * output a csv before use the bulk load
     */
	std::ofstream csv_file;

    /**
     * pointer to mysql driver
     */
    sql::Driver *driver;
    std::shared_ptr<sql::Connection> con;
    std::shared_ptr<sql::ResultSet> result;
};

/**
 * Actual class for the MySQL database connector
 */
class Recon_mysql_DBManager: public RECON_DBManager{
    public:

    /** Constructor
     * @param settings Settings for the database
     */
    Recon_mysql_DBManager(const Recon_DBConfig & db_settings);

    /** Default destructor
     * */
    ~Recon_mysql_DBManager();

    /** Init the effective connection with the database
     * and initialize queries
     */
    void init_database_connection();

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

    /** check if hash is present in db
     * @param key hash to check
     * @return bool if found, false otherwise
     */
    bool check_key(std::string key);

    /** fetch removed hashes from gpg_keyserver 
     *  after a successful recon run. Those hashes
     *  will be removed from the ptree before inserting
     *  the new one
     *  @return vector of hashes to remove
     * */
    std::vector<std::string> fetch_removed_elements();
    
    //empty
    std::vector<std::string> get_all_hash();
    void commit_memtree();
private:

    /**
     * prepared statement for retrieving a particular node
     */
    std::shared_ptr<sql::PreparedStatement> get_pnode_stmt;

    /**
     * prepared statement to insert a new node into the database
     */
    std::shared_ptr<sql::PreparedStatement> insert_pnode_stmt;

    /**
     * prepared statement to update an existing node
     */
    std::shared_ptr<sql::PreparedStatement> update_pnode_stmt;

    /**
     * prepared statement to delete an existing node
     */
    std::shared_ptr<sql::PreparedStatement> delete_pnode_stmt;

    /**
     * prepared statement to fetch all hashes from the certificates
     * table
     */
    std::shared_ptr<sql::PreparedStatement> get_all_hash_stmt;

    /**
     * prepared statement to check if a given hash is
     * present into the certificates table
     */
    std::shared_ptr<sql::PreparedStatement> check_key_stmt;

    /**
     * prepared statement to truncate the table after retrieving 
     * the values
     */
    std::shared_ptr<sql::PreparedStatement> truncate_removed_hash_stmt;

    /**
     * prepared statement to get all the hash to remove from the ptree
     */
    std::shared_ptr<sql::PreparedStatement> get_removed_hash_stmt;

    /**
     * sql query to bulk load from csv the data which will populate
     * the ptree table
     */
	std::pair<std::string,std::string> insert_ptree_stmt;
};

class Recon_memory_DBManager: public RECON_DBManager {
public:
    Recon_memory_DBManager(const Recon_DBConfig & db_settings);
    ~Recon_memory_DBManager();

    /** make the connection with the database if there isn't */
    void init_database_connection();

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

    /** write the memtree to database */
    void commit_memtree();
    
    //empty
    std::vector<std::string> fetch_removed_elements();
private:

    std::map< std::string, std::tuple<std::string, int, bool, std::string> > memory_storage;
    std::shared_ptr<sql::PreparedStatement> get_all_hash_stmt;
    std::shared_ptr<sql::PreparedStatement> check_key_stmt;
	std::pair<std::string,std::string> insert_ptree_stmt;
};


#endif
