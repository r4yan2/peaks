#ifndef RECON_DBMANAGER_H
#define RECON_DBMANAGER_H

#include <vector>
#include <iostream>
#include <common/DBStruct.h>
#include "Recon_settings.h"
#include <fstream>
#include <map>
#include <common/DBManager.h>
#include <recon_daemon/Bitset.h>

using namespace peaks::common;
namespace peaks{
namespace recon{
/** RECON_DBManager class is responsible to
 * manage the connection to the database. The base class is 
 * a virtual one, from which the specific connector inherit
 */
class RECON_DBManager: public DBManager {
public:
    /** Constructor
     * @param settings Settings for the database
     */
    RECON_DBManager();
    ~RECON_DBManager(){};

    /** recover a node from the database
     * @param key key of the node to recover
     * @return node struct corresponding to the found node
     */
    virtual DBStruct::node get_node(const Bitset &key) = 0;
    /** insert node into db
     * @param n node to insert
     */
    virtual void insert_node(const DBStruct::node &n) = 0;
    /** update node already present in db
     * @param n node to update
     */
    virtual void update_node(const DBStruct::node &n) = 0;
    /** delete node from db
     * @param key key of the node to delete
     */
    virtual void delete_node(const Bitset &key) = 0;
    virtual bool check_key(const std::string& key) = 0;
    virtual std::vector<std::string> fetch_removed_elements() = 0;
    virtual std::vector<std::string> get_all_hash() = 0;
    virtual void commit_memtree() = 0;
    virtual void prepare_queries() = 0;
protected:
    /**
     * store a pointer to the csv file which will be needed to 
     * output a csv before use the bulk load
     */
	std::ofstream csv_file;
};

/**
 * Actual class for the MySQL database connector
 */
class Recon_mysql_DBManager: public RECON_DBManager{
    public:

    /** Constructor
     */
    Recon_mysql_DBManager();

    /** recover a node from the database
     * @param key key of the node to recover
     * @return node struct corresponding to the found node
     */
    DBStruct::node get_node(const Bitset &key);

    void insert_node(const DBStruct::node &n);

    /** update node already present in db
     * @param n node to update
     */
    void update_node(const DBStruct::node &n);

    /** delete node from db
     * @param key key of the node to delete
     */
    void delete_node(const Bitset& key);

    /** check if hash is present in db
     * @param key hash to check
     * @return bool if found, false otherwise
     */
    bool check_key(const std::string& key);

    /** fetch removed hashes from gpg_keyserver 
     *  after a successful recon run. Those hashes
     *  will be removed from the ptree before inserting
     *  the new one
     *  @return vector of hashes to remove
     * */
    std::vector<std::string> fetch_removed_elements();

    void prepare_queries();
    
    //empty
    std::vector<std::string> get_all_hash();
    void commit_memtree();
private:

    /**
     * prepared statement for retrieving a particular node
     */
    std::shared_ptr<DBQuery>
        get_pnode_stmt,
        insert_pnode_stmt,
        update_pnode_stmt,
        delete_pnode_stmt,
        get_all_hash_stmt,
        check_key_stmt,
        truncate_removed_hash_stmt,
        get_removed_hash_stmt;

    /**
     * sql query to bulk load from csv the data which will populate
     * the ptree table
     */
	std::pair<std::string,std::string> insert_ptree_stmt;
};

class Recon_memory_DBManager: public RECON_DBManager {
public:
    Recon_memory_DBManager();

    /** @brief prepare queries */
    void prepare_queries();

    /** fetch all hashes from gpg_keyserver table, used
     * to build ptree
     * @return vector of strings representing hashes
     */
    std::vector<std::string> get_all_hash();

    /** check if hash is present in db
     * @param key hash to check
     * @return bool if found, false otherwise
     */
    bool check_key(const std::string& key);

    /** helper to lock tables and avoid unnecessary checks during inserts
     */
    void lockTables();

    /** helper to unlock tables */
    void unlockTables();

    /** write the memtree to database */
    void commit_memtree();
    
    //empty
    std::vector<std::string> fetch_removed_elements();


    DBStruct::node get_node(const Bitset &key);
    void insert_node(const DBStruct::node &n);
    void update_node(const DBStruct::node &n);
    void delete_node(const Bitset &key);

private:

    std::shared_ptr<DBQuery> 
        get_all_hash_stmt,
        check_key_stmt;
	std::pair<std::string,std::string> insert_ptree_stmt;

    /*
     * Map for fast memory tree access
     * key, <node_svalues, num_elemnts, leaf, node_elements>
     */
    std::map<std::pair<std::string, int>, std::tuple<std::vector<NTL::ZZ_p>, int, bool, std::vector<NTL::ZZ_p>> > memory_storage;
};


}
}
#endif
