#ifndef DUMP_DBMANAGER_H
#define DUMP_DBMANAGER_H

#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>
#include <forward_list>
#include <vector>
#include <regex>
#include <Key.h>
#include <iostream>
#include "../common/utils.h"
#include "Config.h"
#include <boost/algorithm/string.hpp>


/** @brief Class manging the database
 * Database manager for the unpacked, it will do the effective data dump into several csv file
 */
class DUMP_DBManager {
    static std::pair<std::string, std::string> 
        dump_gpgkeyserver_stmt,
        dump_pubkey_stmt, 
        dump_signature_stmt, 
        dump_self_signature_stmt, 
        dump_userID_stmt,
        dump_userAtt_stmt, 
        dump_unpackerErrors_stmt,
        dump_brokenKey_stmt;

public:
    /** @brief Database connector constructor
     * init the databasse connector with the settings that
     * will be used to reach the database
     * @param un_settings settings for the database connection
     */
    DUMP_DBManager(const Dump_DBConfig &settings);

    /** @brief Copy constructor
     * This copy constructor is used to parellelize
     * load data by creating another connection
     * istance on the fly
     * @param dbm DBManager istance to copy
     */
    DUMP_DBManager(const std::shared_ptr<DUMP_DBManager> & dbm);

    /** @brief get settings
     * @return settings
     */
    Dump_DBConfig get_settings();
    /** @brief Destructor for the database connector
     * The destructor will just close the file left open
     */
    ~DUMP_DBManager();

    /** @brief Connect to database
     * Actual connection to the database is performed
     * in this method. It will also load all the relevant
     * prepared statement
     */
    void ensure_database_connection();

    /** @brief Dump content of database into CSV 
     * @param f filename of the csv to create
     * @param table source table
     */
    void dumpCSV(const unsigned int &table);

    /** @brief get dump location
     * @return string
     */

    std::string get_dump_path();

private:
    Dump_DBConfig settings;

    std::map<unsigned int, std::ifstream> file_list;

    sql::Driver *driver;

    std::shared_ptr<sql::Connection> con;

    std::string dump_path;

    std::shared_ptr<sql::ResultSet> result;

    std::shared_ptr<sql::PreparedStatement> get_dump_path_stmt; 
};


#endif //DUMP_DBMANAGER_H
