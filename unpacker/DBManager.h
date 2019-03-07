#ifndef UNPACKER_DBMANAGER_H
#define UNPACKER_DBMANAGER_H

#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>
#include <forward_list>
#include <vector>
#include <regex>
#include <Key.h>
#include <iostream>
#include "DBStruct.h"
#include "utils.h"
#include "Config.h"


/** @brief Class manging the database
 * Database manager for the unpacked, it will store data in the csv
 * load the csv into the database, and check expired/revoked/invalid
 * keys after all operations
 */
class UNPACKER_DBManager {
    static std::pair<std::string, std::string> insert_pubkey_stmt, 
        insert_signature_stmt, 
        insert_self_signature_stmt, 
        insert_userID_stmt,
        insert_userAtt_stmt, 
        insert_unpackerErrors_stmt, 
        insert_unpacked_stmt;


public:
    /** @brief Database connector constructor
     * init the databasse connector with the settings that
     * will be used to reach the database
     * @param un_settings settings for the database connection
     */
    UNPACKER_DBManager(const Unpacker_DBConfig &settings);

    /** @brief Copy constructor
     * This copy constructor is used to parellelize
     * load data by creating another connection
     * istance on the fly
     * @param dbm DBManager istance to copy
     */
    UNPACKER_DBManager(const std::shared_ptr<UNPACKER_DBManager> & dbm);

    /** @brief get settings
     * @return settings
     */
    Unpacker_DBConfig get_settings();
    /** @brief Destructor for the database connector
     * The destructor will just close the file left open
     */
    ~UNPACKER_DBManager();

    /** @brief Connect to database
     * Actual connection to the database is performed
     * in this method. It will also load all the relevant
     * prepared statement
     */
    void ensure_database_connection();

    /** @brief Ready CSV files for writing tmp data
     */
    void openCSVFiles();

    /** @brief Recover the certificates to unpack
     * Perform a query on the certificate table to
     * recover the first l certificates to work on
     * @param l number of certificates to retrieve
     * @return certificates data
     */
    std::vector<UNPACKER_DBStruct::gpg_keyserver_data> get_certificates(const unsigned long &l);
    bool existSignature(const UNPACKER_DBStruct::signatures &s);

    /** @brief fill up the Pubkey csv
     * @param pubkey new data to add
     */
    void write_pubkey_csv(const UNPACKER_DBStruct::pubkey &pubkey);
    /** @brief fill up the UserID csv
     * @param uid new data to add
     */
    void write_userID_csv(const UNPACKER_DBStruct::userID &uid);
    /** @brief fill up the userAttributes csv
     * @param userAtt new data to add
     */
    void write_userAttributes_csv(const UNPACKER_DBStruct::userAtt &ua);
    /** @brief fill up the Signature csv
     * @param ss new data to add
     */
    void write_signature_csv(const UNPACKER_DBStruct::signatures &ss);
    /** @brief fill up the SelfSignatures csv
     * @param ss new data to add
     */
    void write_self_signature_csv(const UNPACKER_DBStruct::signatures &ss);
    /** @brief fill up the UnpackerErrors csv
     * @param mod new data to add
     */
    void write_unpackerErrors_csv(const UNPACKER_DBStruct::Unpacker_errors &mod);
    /** @brief fill the Unpacked csv
     * Will be used to change the status of the is_unpacked flag
     * in the certificates table
     * @param key certificate for which change the unpacked value
     * @param mod information about the unpacking status
     */
    void write_unpacked_csv(const OpenPGP::Key::Ptr &key, const UNPACKER_DBStruct::Unpacker_errors &mod);

    /** @brief Bulk-insert CSV into the database
     * Insert multiple csv into the respective table 
     * of the database via LOAD DATA INFILE operation
     * @param f filename of the csv to insert in the database
     * @param table target table 
     */
    void insertCSV(const std::string &f, const unsigned int &table);

    void set_as_not_analyzable(const int &version, const std::string &fingerprint, const std::string &comment);

    /** @brief Updates issuing fingerprint 
     * Update issuing signatures fingerprint in the signatures table
     * @param l limit of the query
     */
    void UpdateSignatureIssuingFingerprint(const unsigned long &l);

    /** @brief Scan the databsae for expired keys
     */
    void UpdateIsExpired();

    /** @brief Scan the database for revoked keys
     */
    void UpdateIsRevoked();

    /** @brief Scan the database for invalid keys
     */
    void UpdateIsValid();

    void UpdateSignatureIssuingUsername();

private:
    Unpacker_DBConfig settings;

    std::map<unsigned int, std::ofstream> file_list;

    sql::Driver *driver;

    std::shared_ptr<sql::Connection> con;

    std::shared_ptr<sql::ResultSet> result;

    std::shared_ptr<sql::PreparedStatement> get_analyzable_cert_stmt, 
        get_signature_by_index, 
        set_key_not_analyzable,
        insert_error_comments,
        insert_issuing_fingerprint,
        set_unpacking_status_stmt;


};


#endif //UNPACKER_DBMANAGER_H
