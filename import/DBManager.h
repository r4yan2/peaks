#ifndef IMPORT_DBMANAGER_H
#define IMPORT_DBMANAGER_H

#include <forward_list>
#include <vector>
#include <Key.h>
#include <iostream>
#include "DBStruct.h"
#include "Config.h"
#include "../common/utils.h"
#include "../common/DBManager.h"

namespace DBStruct = IMPORT_DBStruct;
class IMPORT_DBManager: public DBManager {
public:

    IMPORT_DBManager(const DBSettings  & settings_, const ImportFolders & folders_);
    IMPORT_DBManager(const std::shared_ptr<IMPORT_DBManager> & dbm_);
    ~IMPORT_DBManager();
    ImportFolders get_folders();

    bool existSignature(const DBStruct::signatures &s);
    void prepare_queries();
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

    void insertCSV(const std::string & f, const unsigned int &table);

    void UpdateIsExpired();
    void UpdateIsRevoked();
    void UpdateIsValid();

    void UpdateSignatureIssuingUsername();

private:

    ImportFolders folders;
    std::map<unsigned int, std::ofstream> file_list;

    static std::pair<std::string, std::string> 
        insert_pubkey_stmt, 
        insert_signature_stmt, 
        insert_self_signature_stmt,
        insert_userID_stmt, 
        insert_unpackerErrors_stmt, 
        insert_certificate_stmt, 
        insert_brokenKey_stmt, 
        insert_userAtt_stmt;

    std::shared_ptr<DBQuery>
        get_signature_by_index;
};

#endif //UNPACKER_DBMANAGER_H
