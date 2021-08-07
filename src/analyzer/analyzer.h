#ifndef ANALYZER_ANALYZER_H
#define ANALYZER_ANALYZER_H
#include <vector>
#include <iostream>
#include "DBManager.h"
#include <boost/program_options.hpp>
#include <common/DBStruct.h>

namespace po = boost::program_options;
using namespace peaks::common;
namespace peaks{
namespace analyzer{

class Analyzer {
public:
    Analyzer(po::variables_map &vm);
    void run();
    void analyze_pubkeys(const std::vector<DBStruct::pubkey> &pks) const;
    void analyze_signatures(const std::vector<DBStruct::signatures> &ss) const;

    void analyze_RSA_modulus_common_factor(const std::shared_ptr<ANALYZER_DBManager> &dbm, const unsigned int &nThreads);

private:
    DBSettings db_settings;
    unsigned int nThreads,limit,key_per_thread;

    std::shared_ptr<ANALYZER_DBManager> dbm;
    void analyze_pubkey(DBStruct::pubkey pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    void ELGAMAL_DSA_subgroup_size_check(const unsigned int &q, DBStruct::KeyStatus &ks, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    void ELGAMAL_DSA_group_size_check(const unsigned int &p, DBStruct::KeyStatus &ks, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    void analyze_signature(const DBStruct::signatures &sign, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;

    void check_RSA(const DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    //void check_DSA(const DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    //void check_Elgamal(const DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    void check_Elgamal_DSA(const DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    void check_Curve(const DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    bool check_signature(const DBStruct::signatures &sign, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;

};

}
}

#endif //ANALYZER_ANALYZER_H