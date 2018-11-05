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

class UNPACKER_DBManager {
public:
    UNPACKER_DBManager();
    ~UNPACKER_DBManager();

    void openCSVFiles();

    std::vector<UNPACKER_DBStruct::gpg_keyserver_data> get_certificates(const unsigned long &l);
    bool existSignature(const UNPACKER_DBStruct::signatures &s);

    void write_pubkey_csv(const UNPACKER_DBStruct::pubkey &pubkey);
    void write_userAttributes_csv(const UNPACKER_DBStruct::userAtt &ua);
    void write_signature_csv(const UNPACKER_DBStruct::signatures &ss);
    void write_self_signature_csv(const UNPACKER_DBStruct::signatures &ss);
    void write_unpackerErrors_csv(const UNPACKER_DBStruct::Unpacker_errors &mod);
    void write_unpacked_csv(const OpenPGP::PublicKey::Ptr &key, const UNPACKER_DBStruct::Unpacker_errors &mod);

    void insertCSV(const std::vector<std::string> &files, const unsigned int &table);

    void set_as_not_analyzable(const int &version, const std::string &fingerprint, const std::string &comment);

    void UpdateSignatureIssuingFingerprint(const unsigned long &l);

    void UpdateIsExpired();
    void UpdateIsRevoked();
    void UpdateIsValid();

    void UpdateSignatureIssuingUsername();

private:
    std::map<unsigned int, std::ofstream> file_list;

    sql::Driver *driver;
    std::shared_ptr<sql::Connection> con;
    std::shared_ptr<sql::PreparedStatement> get_analyzable_cert_stmt, get_signature_by_index, set_key_not_analyzable,
            insert_error_comments, insert_issuing_fingerprint;
    std::shared_ptr<sql::ResultSet> result;

    std::pair<std::string, std::string> insert_pubkey_stmt, insert_signature_stmt, insert_self_signature_stmt,
            insert_userAtt_stmt, insert_unpackerErrors_stmt, insert_unpacked_stmt;

};


#endif //UNPACKER_DBMANAGER_H
