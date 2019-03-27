#ifndef IMPORT_DBMANAGER_H
#define IMPORT_DBMANAGER_H


#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>
#include <forward_list>
#include <vector>
#include <regex>
#include <Key.h>
#include <iostream>
#include "DBStruct.h"
#include "Config.h"
#include "../common/utils.h"

namespace DBStruct = IMPORT_DBStruct;
class IMPORT_DBManager {
public:
    IMPORT_DBManager(const Import_DBConfig &settings_);
    ~IMPORT_DBManager();

    void init_database_connection();
    bool existSignature(const DBStruct::signatures &s);

    void write_pubkey_csv(const DBStruct::pubkey &pubkey);
    void write_userAttributes_csv(const DBStruct::userAtt &uid);
    void write_userID_csv(const DBStruct::userID &uid);
    void write_signature_csv(const DBStruct::signatures &ss);
    void write_self_signature_csv(const DBStruct::signatures &ss);
    void write_unpackerErrors_csv(const DBStruct::Unpacker_errors &mod);
    void write_gpg_keyserver_csv(const DBStruct::gpg_keyserver_data &gpg_data, const int is_unpacked);

    void write_broken_key_csv(std::ifstream &file_cert, const std::string &error);


    void UpdateSignatureIssuingFingerprint();
    void lockTables();

    void unlockTables();

    void openCSVFiles();

    void insertCSV(const std::vector<std::string> &files, const unsigned int &table);

    void UpdateIsExpired();
    void UpdateIsRevoked();
    void UpdateIsValid();

    void UpdateSignatureIssuingUsername();

private:

    Import_DBConfig settings;
    std::map<unsigned int, std::ofstream> file_list;
    sql::Driver *driver;
    std::shared_ptr<sql::Connection> con;

    std::shared_ptr<sql::PreparedStatement> get_signature_by_index;

    std::shared_ptr<sql::ResultSet> result;

    std::pair<std::string, std::string> insert_pubkey_stmt, insert_signature_stmt, insert_self_signature_stmt,
            insert_userID_stmt, insert_unpackerErrors_stmt, insert_certificate_stmt, insert_brokenKey_stmt, insert_userAtt_stmt;

};


#endif //UNPACKER_DBMANAGER_H
