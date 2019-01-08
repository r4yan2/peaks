#ifndef ANALYZER_ANALYZER_H
#define ANALYZER_ANALYZER_H


#include "DBStruct.h"
#include "DBManager.h"
#include <boost/program_options.hpp>

namespace po = boost::program_options;

class Analyzer {
public:
    Analyzer(std::shared_ptr<ANALYZER_DBManager> &dbptr, const Analyzer_DBConfig &db_settings);
    void analyze_pubkeys(const std::vector<ANALYZER_DBStruct::pubkey> &pks) const;
    void analyze_signatures(const std::vector<ANALYZER_DBStruct::signatures> &ss) const;

    void analyze_RSA_modulus_common_factor(const std::shared_ptr<ANALYZER_DBManager> &dbm, const unsigned int &nThreads);

private:
    Analyzer_DBConfig settings;
    std::shared_ptr<ANALYZER_DBManager> dbm;
    void analyze_pubkey(ANALYZER_DBStruct::pubkey pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    void ELGAMAL_DSA_subgroup_size_check(const unsigned int &q, ANALYZER_DBStruct::KeyStatus &ks, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    void ELGAMAL_DSA_group_size_check(const unsigned int &p, ANALYZER_DBStruct::KeyStatus &ks, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    void analyze_signature(const ANALYZER_DBStruct::signatures &sign, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;

    void check_RSA(const ANALYZER_DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    //void check_DSA(const ANALYZER_DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    //void check_Elgamal(const ANALYZER_DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    void check_Elgamal_DSA(const ANALYZER_DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    void check_Curve(const ANALYZER_DBStruct::pubkey &pk, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;
    bool check_signature(const ANALYZER_DBStruct::signatures &sign, const std::shared_ptr<ANALYZER_DBManager> &dbm) const;

};

int analyzer(po::variables_map &vm);


#endif //ANALYZER_ANALYZER_H
