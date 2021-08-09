#ifndef ANALYZER_DBMANAGER_H
#define ANALYZER_DBMANAGER_H


#include <forward_list>
#include <vector>
#include <map>
#include <NTL/ZZ.h>
#include <regex>
#include <Key.h>
#include "Math_Support.h"
#include <common/DBManager.h>
#include <common/DBStruct.h>

using namespace peaks::common;
namespace peaks{
namespace analyzer{
class ANALYZER_DBManager: public DBManager {
public:
    ANALYZER_DBManager();
    ~ANALYZER_DBManager();
    void open_pubkey_files();
    void open_signatures_files();

    std::vector<DBStruct::pubkey> get_pubkey(const unsigned long &l);
    std::vector<DBStruct::signatures> get_signatures(const unsigned long &l);
    std::vector<NTL::ZZ> get_RSA_modulus();
    void write_repeated_r_csv();
    //bool search_signature(const NTL::ZZ &r);
    //std::map<char, NTL::ZZ> getPubValues(DBStruct::signatures s);

    void write_broken_signature_csv(const DBStruct::SignatureStatus &ss);
    void write_broken_key_csv(const DBStruct::KeyStatus &ks);
    void write_broken_modulus_csv(const std::vector<std::string> &broken_modulus);

    void insertCSV(const std::vector<std::string> &files, const unsigned int &table);

    void write_analyzed_pk_csv(const DBStruct::pubkey &pk);

    void write_analyzed_sign_csv(const DBStruct::signatures &s);

private:
    std::map<unsigned int, std::ofstream> file_list;

    void prepare_queries();

    std::shared_ptr<DBQuery>
        get_repeated_r_stmt,
        get_analyzable_pubkey_stmt,
        get_analyzable_signature_stmt,
        get_RSA_modulo_list_stmt,
        get_MPI_pubkey_stmt,
        commit_stmt;

    std::pair<std::string, std::string> 
        set_pubkey_analyzed_stmt, 
        set_analyzed_signature_stmt, 
        insert_broken_key_stmt,
        insert_broken_signature_stmt, 
        insert_broken_modulus_stmt, 
        insert_repeated_r_stmt;

};

}
}

#endif //UNPACKER_DBMANAGER_H
