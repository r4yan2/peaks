#ifndef IMPORT_DBMANAGER_H
#define IMPORT_DBMANAGER_H

#include <forward_list>
#include <vector>
#include <Key.h>
#include <iostream>
#include <common/DBStruct.h>
#include <common/utils.h>
#include <common/DBManager.h>
#include <common/Thread_Pool.h>

using namespace peaks::common;

namespace peaks{
namespace import{
class IMPORT_DBManager: public DBManager {
public:

    IMPORT_DBManager();
    ~IMPORT_DBManager();

    bool existSignature(const DBStruct::signatures &s);
    void prepare_queries();
    void write_pubkey_csv(const DBStruct::pubkey &pubkey);
    void write_userAttributes_csv(const DBStruct::userAtt &uid);
    void write_userID_csv(const DBStruct::userID &uid);
    void write_signature_csv(const DBStruct::signatures &ss);
    void write_self_signature_csv(const DBStruct::signatures &ss);
    void write_unpackerErrors_csv(const DBStruct::Unpacker_errors &mod);
    void write_gpg_keyserver_csv(const DBStruct::gpg_keyserver_data &gpg_data);

    void write_broken_key_csv(std::ifstream &file_cert, const std::string &error);


    void UpdateSignatureIssuingFingerprint();
	void drop_index_gpg_keyserver();
	void build_index_gpg_keyserver();

    void UpdateIsExpired();
    void UpdateIsRevoked();
    void UpdateIsValid();

    void UpdateSignatureIssuingUsername();

private:

    std::shared_ptr<DBQuery>
        get_signature_by_index;
};

}
}
#endif //UNPACKER_DBMANAGER_H
