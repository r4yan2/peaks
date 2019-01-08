#ifndef ANALYZER_DBMANAGER_H
#define ANALYZER_DBMANAGER_H


#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>
#include <forward_list>
#include <vector>
#include <map>
#include <NTL/ZZ.h>
#include <regex>
#include <Key.h>
#include "DBStruct.h"
#include "Math_Support.h"
#include "Config.h"

class ANALYZER_DBManager {
public:
    ANALYZER_DBManager(Analyzer_DBConfig &settings);
    ~ANALYZER_DBManager();
    void open_pubkey_files();
    void open_signatures_files();

    std::vector<ANALYZER_DBStruct::pubkey> get_pubkey(const unsigned long &l);
    std::vector<ANALYZER_DBStruct::signatures> get_signatures(const unsigned long &l);
    std::vector<NTL::ZZ> get_RSA_modulus();
    void write_repeated_r_csv();
    //bool search_signature(const NTL::ZZ &r);
    //std::map<char, NTL::ZZ> getPubValues(ANALYZER_DBStruct::signatures s);

    void write_broken_signature_csv(const ANALYZER_DBStruct::SignatureStatus &ss);
    void write_broken_key_csv(const ANALYZER_DBStruct::KeyStatus &ks);
    void write_broken_modulus_csv(const std::vector<std::string> &broken_modulus);

    void insertCSV(const std::vector<std::string> &files, const unsigned int &table);

    void write_analyzed_pk_csv(const ANALYZER_DBStruct::pubkey &pk);

    void write_analyzed_sign_csv(const ANALYZER_DBStruct::signatures &s);

private:
    Analyzer_DBConfig settings;

    std::map<unsigned int, std::ofstream> file_list;

    sql::Driver *driver;
    std::shared_ptr<sql::Connection> con;
    std::shared_ptr<sql::PreparedStatement> get_analyzable_pubkey_stmt, get_analyzable_signature_stmt,
            get_RSA_modulo_list_stmt, get_MPI_pubkey_stmt;
    std::shared_ptr<sql::ResultSet> result;

    std::pair<std::string, std::string> set_pubkey_analyzed_stmt, set_analyzed_signature_stmt, insert_broken_key_stmt,
            insert_broken_signature_stmt, insert_broken_modulus_stmt, insert_repeated_r_stmt;

};


#endif //UNPACKER_DBMANAGER_H
