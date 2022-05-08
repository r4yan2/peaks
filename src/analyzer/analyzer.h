#ifndef ANALYZER_ANALYZER_H
#define ANALYZER_ANALYZER_H
#include <vector>
#include <iostream>
#include "DBManager.h"
#include <boost/program_options.hpp>
#include <common/DBStruct.h>

using namespace peaks::common;
namespace peaks{
namespace analyzer{
    void analyze();

class Analyzer {
public:
    Analyzer();
    void run();
    void import_csv(const std::shared_ptr<ANALYZER_DBManager> &dbm);
private:
    unsigned int nThreads,limit,key_per_thread;
};
    void analyze_pubkeys(const std::vector<DBStruct::pubkey> &pks);
    void analyze_signatures(const std::vector<DBStruct::signatures> &ss, const std::shared_ptr<ANALYZER_DBManager> &);

    void analyze_RSA_modulus_common_factor(const std::shared_ptr<ANALYZER_DBManager> &dbm, const unsigned int &nThreads);

    void analyze_pubkey(DBStruct::pubkey pk, const std::shared_ptr<ANALYZER_DBManager> &dbm);
    void ELGAMAL_DSA_subgroup_size_check(const unsigned int &q, DBStruct::KeyStatus &ks, const std::shared_ptr<ANALYZER_DBManager> &dbm);
    void ELGAMAL_DSA_group_size_check(const unsigned int &p, DBStruct::KeyStatus &ks, const std::shared_ptr<ANALYZER_DBManager> &dbm);
    void analyze_signature(const DBStruct::signatures &sign, const std::shared_ptr<ANALYZER_DBManager> &dbm);

    void check_RSA(const DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm);
    //void check_DSA(const DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    //void check_Elgamal(const DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    void check_Elgamal_DSA(const DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm);
    void check_Curve(const DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm);
    bool check_signature(const DBStruct::signatures &sign, const std::shared_ptr<ANALYZER_DBManager> &dbm);


}
}

#endif //ANALYZER_ANALYZER_H
