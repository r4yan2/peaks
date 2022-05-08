#include <PKA/PKAs.h>
#include <Hashes/Hashes.h>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include "analyzer.h"
#include "EC_point.h"
#include "fastGCD.h"
#include "ED_point.h"
#include <common/utils.h>
#include <string.h>
#include <Misc/PKCS1.h>
#include <gcrypt.h>
#include <common/Thread_Pool.h>
#include <common/config.h>

using namespace OpenPGP;
using namespace NTL;
using namespace std;
using namespace peaks::common::DBStruct;
using namespace peaks::analyzer::Math_Support;
using namespace peaks::common::Utils;

namespace peaks{
namespace analyzer{

void analyze(){
    Analyzer alz;
    int iterations = CONTEXT.get<int>("only");
    while(true){
    	alz.run();
        if (iterations > 0)
            iterations--;
        if (iterations == 0){
            syslog(LOG_INFO, "Done %d iterations!", CONTEXT.get<int>("only"));
            break;
        }
    	std::this_thread::sleep_for(std::chrono::seconds{CONTEXT.get<int>("analyzer_interval")});
    }
}

Analyzer::Analyzer()
{
    syslog(LOG_NOTICE, "Analyzer daemon is starting up!");

    if(Utils::create_folders(CONTEXT.get<std::string>("tmp_folder")) == -1){
        syslog(LOG_WARNING, "Unable to create temp folder");
        exit(-1);
    }
    if (Utils::create_folders(CONTEXT.get<std::string>("error_folder")) == -1){
        syslog(LOG_WARNING, "Unable to create temp folder");
        exit(-1);
    }

    syslog(LOG_INFO, "Starting pubkey analysis");
    nThreads = CONTEXT.get<int>("threads", 1);
    
    syslog(LOG_NOTICE, "Using %d Threads", nThreads);
 
    limit = CONTEXT.get<int>("limit", CONTEXT.get<int>("analyzer_limit"));

    syslog(LOG_NOTICE, "Limiting analysis to %u certificates", limit);
 
    key_per_thread = 1 + ((limit - 1)/nThreads);
     
}

void Analyzer::run(){
 
    std::shared_ptr<ANALYZER_DBManager> dbm = std::make_shared<ANALYZER_DBManager>();
    std::string status = "";
    dbm->get_from_cache("analyzer_status", status);
    if (status == "ready"){
        syslog(LOG_NOTICE, "Found old session to resume");
        import_csv(dbm);
    }
    bool exist_rsa = false;
    dbm->openCSVFiles();

    shared_ptr<Thread_Pool> pool = make_shared<Thread_Pool>(nThreads);

    vector<DBStruct::pubkey> pk = dbm->get_pubkey(limit);
    for (unsigned int i = 0; i < pk.size();){
        vector<DBStruct::pubkey> pks;
        exist_rsa = PKA::is_RSA(pk[i].pubAlgorithm);
        for (unsigned int j = 0; i < pk.size() && j < key_per_thread; j++, i++){
            pks.push_back(pk[i]);
        }
        pool->Add_Job([=] { analyze_pubkeys(pks); });
    }

    syslog(LOG_INFO, "Starting RSA modulus analysis");

    if (!pk.empty() && exist_rsa){
        analyze_RSA_modulus_common_factor(dbm, nThreads);
    }

    syslog(LOG_INFO, "Starting signature analysis");

    vector<DBStruct::signatures> ss = dbm->get_signatures(limit);

    for (unsigned int i = 0; i < ss.size();){
        vector<DBStruct::signatures> sss;
        for (unsigned int j = 0; i < ss.size() && j < key_per_thread; i++, j++){
            sss.push_back(ss[i]);
        }
        pool->Add_Job([=] { return analyze_signatures(sss, dbm); });
    }

    pool->Add_Job([&] { return dbm->write_repeated_r_csv(); });

    pool->terminate();
    dbm->closeCSVFiles();
    import_csv(dbm);
    syslog(LOG_NOTICE, "Analyzer daemon is stopping!");
}

void Analyzer::import_csv(const std::shared_ptr<ANALYZER_DBManager> &dbm){
    if (CONTEXT.get<bool>("csv-only", false))
        return; //nothing to do
    syslog(LOG_NOTICE, "Writing data to DB");
    dbm->store_in_cache("analyzer_status", "ready");
    dbm->insertCSV(Utils::ANALYZER_FILES::BROKEN_PUBKEY);
    dbm->insertCSV(Utils::ANALYZER_FILES::ANALYZED_PUBKEY);
    dbm->insertCSV(Utils::ANALYZER_FILES::BROKEN_MODULUS);
    dbm->insertCSV(Utils::ANALYZER_FILES::BROKEN_SIGNATURE);
    dbm->insertCSV(Utils::ANALYZER_FILES::REPEATED_R);
    dbm->insertCSV(Utils::ANALYZER_FILES::ANALYZED_SIGNATURE);
    dbm->store_in_cache("analyzer_status", "done");
    syslog(LOG_NOTICE, "Writing completed");
}

void analyze_pubkeys(const vector<DBStruct::pubkey> &pks) {
    std::shared_ptr<ANALYZER_DBManager> dbm = make_shared<ANALYZER_DBManager>();
    dbm->openCSVFiles();
    
    for (const auto &pk: pks){
        try{
            analyze_pubkey(pk, dbm);
        }catch (exception &e){
            syslog(LOG_CRIT, "Pubkey analyzing failed! - %s", e.what());
        }
    }
}

void analyze_signatures(const std::vector<DBStruct::signatures> &ss, const std::shared_ptr<ANALYZER_DBManager> &dbm){

    for (const auto &s: ss){
        try{
            analyze_signature(s, dbm);
        }catch (exception &e){
            syslog(LOG_CRIT, "Signature analyzing failed! - %s", e.what());
        }
    }
}

void analyze_pubkey(DBStruct::pubkey pk, const shared_ptr<ANALYZER_DBManager> &dbm){
    switch (pk.pubAlgorithm){
        case PKA::ID::RSA_ENCRYPT_ONLY:
        case PKA::ID::RSA_SIGN_ONLY:
        case PKA::ID::RSA_ENCRYPT_OR_SIGN:
            check_RSA(pk, dbm);
            break;
        case PKA::ID::ELGAMAL:
        //case PKA::ID::RESERVED_ELGAMAL:
        case PKA::ID::DSA:
            check_Elgamal_DSA(pk, dbm);
            break;
        case PKA::ID::ECDSA:
        case PKA::ID::EdDSA:
        case PKA::ID::ECDH:
            check_Curve(pk, dbm);
            break;
        default:
            break;
    }

    dbm->write_analyzed_pk_csv(pk);
}

void analyze_signature(const DBStruct::signatures &sign, const shared_ptr<ANALYZER_DBManager> &dbm){
    SignatureStatus ss = {
         signature_id : sign.id
    };
    // Check hash algorithm
    try{
        if (sign.hashAlgorithm == Hash::ID::MD5){
            ss.vulnerabilityCode = VULN_CODE::SIGNATURE_MD5_USED;
            ss.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::SIGNATURE_MD5_USED);
            dbm->write_broken_signature_csv(ss);
        }
    }catch (exception &e){
        ss.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::SIGNATURE_MD5_USED;
        ss.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check signature MD5 - " + e.what();
        dbm->write_broken_signature_csv(ss);
    }

    // Check inconsistent use
    try{
        if (!PKA::can_sign(sign.pubAlgorithm)){
            ss.vulnerabilityCode = VULN_CODE::SIGNATURE_WRONG_ALG;
            ss.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::SIGNATURE_WRONG_ALG);
            dbm->write_broken_signature_csv(ss);
        }
    }catch (exception &e){
        ss.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::SIGNATURE_WRONG_ALG;
        ss.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check signature inconsistent algorithm - " + e.what();
        dbm->write_broken_signature_csv(ss);
    }

    // check signature
    if (PKA::can_sign(sign.pubAlgorithm) || sign.pubAlgorithm == PKA::ID::ELGAMAL){
        try{
            //if (sign.hashHeader == sign.signedHash.substr(0, 2) && (sign.pk_status < 7 || sign.pk_status == 9)){
            if ((sign.pk_status < Utils::VULN_CODE::DSA_ELGAMAL_P_PRIME || sign.pk_status == Utils::VULN_CODE::DSA_ELGAMAL_G_SUBGROUP)){
                if (!check_signature(sign, dbm)){
                    ss.vulnerabilityCode = VULN_CODE::SIGNATURE_WRONG_CHECK;
                    ss.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::SIGNATURE_WRONG_CHECK);
                    dbm->write_broken_signature_csv(ss);
                }
            }else{
                ss.vulnerabilityCode = VULN_CODE::CANNOT_CHECK_SIGNATURE;
                ss.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::CANNOT_CHECK_SIGNATURE);
                dbm->write_broken_signature_csv(ss);
            }
        }catch (exception &e){
            ss.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::SIGNATURE_WRONG_CHECK;
            ss.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check signature - " + e.what();
            dbm->write_broken_signature_csv(ss);
        }
    }

    // Check is exportable
    try{
        if (!sign.isExportable){
            ss.vulnerabilityCode = VULN_CODE::SIGNATURE_NOT_EXPORTABLE;
            ss.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::SIGNATURE_NOT_EXPORTABLE);
            dbm->write_broken_signature_csv(ss);
        }
    }catch (exception &e){
        ss.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::SIGNATURE_NOT_EXPORTABLE;
        ss.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check signature exportable - " + e.what();
        dbm->write_broken_signature_csv(ss);
    }
    dbm->write_analyzed_sign_csv(sign);
}

void check_RSA(const DBStruct::pubkey &pk, const shared_ptr<ANALYZER_DBManager> &dbm){
    KeyStatus ks = {
            .version = pk.version,
            .fingerprint = pk.fingerprint
    };

    // Check values exist
    try{
        if(pk.e == 0 || pk.n == 0){
            ks.vulnerabilityCode = VULN_CODE::ERROR;
            ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check RSA values";
            dbm->write_broken_key_csv(ks);
            return;
        }
    }catch (exception &e){
        ks.vulnerabilityCode = VULN_CODE::ERROR;
        ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check RSA values. " + e.what();
        dbm->write_broken_key_csv(ks);
        return;
    }

    // Key Size Check
    try{
        if (NumBits(pk.n) <= RSA_BREAKABLE_SIZE) {
            ks.vulnerabilityCode = VULN_CODE::OUTDATED_KEY_SIZE;
            ks.vulnerabilityDescription = "KeySize breakable: " + to_string(NumBits(pk.n));
            dbm->write_broken_key_csv(ks);
        } else if ((NumBits(pk.n) > RSA_BREAKABLE_SIZE) and (NumBits(pk.n) < RSA_UNSAFE_SIZE)){
            ks.vulnerabilityCode = VULN_CODE::OUTDATED_KEY_SIZE;
            ks.vulnerabilityDescription = "KeySize unsafe: " + to_string(NumBits(pk.n));
            dbm->write_broken_key_csv(ks);
        } else if ((NumBits(pk.n) > RSA_UNSAFE_SIZE) and (NumBits(pk.n) < RSA_ADVISED_SIZE)) {
            ks.vulnerabilityCode = VULN_CODE::OUTDATED_KEY_SIZE;
            ks.vulnerabilityDescription = "KeySize below advised threshold: " + to_string(NumBits(pk.n));
            dbm->write_broken_key_csv(ks);
        }
    }catch (exception &e){
        ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::OUTDATED_KEY_SIZE;
        ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check RSA size - " + e.what();
        dbm->write_broken_key_csv(ks);
    }

    // Prime Test
    try{
        if (ProbPrime(pk.n, 32)) {
        //if (Math_Support::PrimeTest(pk.n)) {
            ks.vulnerabilityCode = VULN_CODE::RSA_PRIME_MODULUS;
            ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::RSA_PRIME_MODULUS);
            dbm->write_broken_key_csv(ks);
        }else{
            // Low factor
            try {
                ZZ gcd = GCD(FIRST_3000_PRIME, pk.n);
                if (gcd != 1){
                    ks.vulnerabilityCode = VULN_CODE::RSA_LOW_FACTOR;
                    ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::RSA_LOW_FACTOR) + Math_Support::zz_to_string(gcd);
                    dbm->write_broken_key_csv(ks);
                }
            }catch (exception &e){
                ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::RSA_LOW_FACTOR;
                ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check RSA low factor - " + e.what();
                dbm->write_broken_key_csv(ks);
            }
        }
    }catch (exception &e){
        ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::RSA_PRIME_MODULUS;
        ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check RSA modulus - " + e.what();
        dbm->write_broken_key_csv(ks);
    }

    // Exponent Size Check
    try{
        if (pk.e < RSA_MINIMUM_EXP_SIZE) {
            ks.vulnerabilityCode = VULN_CODE::RSA_EXP;
            ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::RSA_EXP) + Math_Support::zz_to_string(pk.e);
            dbm->write_broken_key_csv(ks);
        }
    }catch (exception &e){
        ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::RSA_EXP;
        ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check RSA exponent - " + e.what();
        dbm->write_broken_key_csv(ks);
    }

    // ROCA
    try{
        if (Math_Support::roca_test(pk.n)){
            ks.vulnerabilityCode = VULN_CODE::RSA_ROCA;
            ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::RSA_ROCA);
            dbm->write_broken_key_csv(ks);
        }
    }catch (exception &e){
        ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::RSA_ROCA;
        ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check RSA ROCA vulnerability - " + e.what();
        dbm->write_broken_key_csv(ks);
    }
}
void check_Curve(const DBStruct::pubkey &pk, const shared_ptr<ANALYZER_DBManager> &dbm){
    KeyStatus ks = {
            .version = pk.version,
            .fingerprint = pk.fingerprint
    };

    if (!PKA::right_curve(pk.pubAlgorithm, pk.curve)){
        ks.vulnerabilityCode = Utils::VULN_CODE::CURVE_WRONG;
        ks.vulnerabilityDescription = Utils::VULN_NAME.at(Utils::VULN_CODE::CURVE_WRONG);
        dbm->write_broken_key_csv(ks);
    }
    string complete_point = mpitoraw(zz_to_mpi(pk.p));
    string point = complete_point.substr(1);
    string flag = hexlify(complete_point.substr(0,1));
    const string curve_OID = hexlify(unhexlify(pk.curve), true);

    if (flag == "04" && pk.pubAlgorithm != PKA::ID::EdDSA){ // Standard flag for uncompressed format
        ZZ x = conv<ZZ>(mpitodec(rawtompi(point.substr(0, point.size() / 2))).c_str());
        ZZ y = conv<ZZ>(mpitodec(rawtompi(point.substr(point.size() / 2))).c_str());

        shared_ptr<Elliptic_Curve> curve = make_shared<Elliptic_Curve>(Elliptic_Curve(curve_OID));
        EC_point P = EC_point(x, y, curve);
        if (!P.onItsCurve()){
            ks.vulnerabilityCode = Utils::VULN_CODE::CURVE_POINT_NotOnCurve;
            ks.vulnerabilityDescription = VULN_NAME.at(Utils::VULN_CODE::CURVE_POINT_NotOnCurve);
            dbm->write_broken_key_csv(ks);
        }
        return;
    } else if (flag == "40"){// && pk.pubAlgorithm != PKA::ID::ECDSA){ // Native point format of the curve follows
        if (curve_OID == PKA::CURVE_OID::ED_255){ // Ed25519 - EdDSA
            shared_ptr<Edward_Curve> curve = make_shared<Edward_Curve>(curve_OID);
            try{
                ED_point P = ED_point(point, curve);
                return;
            }catch (runtime_error &e){
                ks.vulnerabilityCode = Utils::VULN_CODE::CURVE_POINT_NotOnCurve;
                ks.vulnerabilityDescription = VULN_NAME.at(Utils::VULN_CODE::CURVE_POINT_NotOnCurve);
                dbm->write_broken_key_csv(ks);
                return;
            }catch (exception &e){
                ks.vulnerabilityCode = Utils::VULN_CODE::ERROR + Utils::VULN_CODE::CURVE_POINT_NotOnCurve;
                ks.vulnerabilityDescription = VULN_NAME.at(Utils::VULN_CODE::ERROR) + "decode 0x40 point";
                dbm->write_broken_key_csv(ks);
                return;
            }
        } else if (curve_OID == PKA::CURVE_OID::CURVE_255){ // Curve25519 - ECDH
            // Nothing to test
            return;
        } else if (PKA::is_EC(curve_OID)){
            shared_ptr<Elliptic_Curve> curve = make_shared<Elliptic_Curve>(curve_OID);
            try{
                EC_point P = EC_point(point, curve);
                return;
            }catch (std::runtime_error &e){
                ks.vulnerabilityCode = Utils::VULN_CODE::CURVE_POINT_NotOnCurve;
                ks.vulnerabilityDescription = VULN_NAME.at(Utils::VULN_CODE::CURVE_POINT_NotOnCurve);
                dbm->write_broken_key_csv(ks);
                return;
            }catch (exception &e){
                ks.vulnerabilityCode = Utils::VULN_CODE::ERROR + Utils::VULN_CODE::CURVE_POINT_NotOnCurve;
                ks.vulnerabilityDescription = VULN_NAME.at(Utils::VULN_CODE::ERROR) + "decode 0x40 point";
                dbm->write_broken_key_csv(ks);
                return;
            }
        }
        else{
            ks.vulnerabilityCode = Utils::VULN_CODE::ERROR + Utils::VULN_CODE::CURVE_WRONG;
            ks.vulnerabilityDescription = VULN_NAME.at(Utils::VULN_CODE::ERROR) + "CURVE NOT FOUND!!";
            dbm->write_broken_key_csv(ks);
            return;
        }
    } else if (flag == "41" && pk.pubAlgorithm != PKA::ID::EdDSA){ // Only X coordinate follows
        ks.vulnerabilityCode = Utils::VULN_CODE::ERROR;
        ks.vulnerabilityDescription = VULN_NAME.at(Utils::VULN_CODE::ERROR) + "Flag 0x41 not implemented!!";
        dbm->write_broken_key_csv(ks);
        return;
    } else if (flag == "42" && pk.pubAlgorithm != PKA::ID::EdDSA){ // Only Y coordinate follows
        ks.vulnerabilityCode = Utils::VULN_CODE::ERROR;
        ks.vulnerabilityDescription = VULN_NAME.at(Utils::VULN_CODE::ERROR) + "Flag 0x42 not implemented!!";
        dbm->write_broken_key_csv(ks);
        return;
    } else{
        ks.vulnerabilityCode = Utils::VULN_CODE::ERROR + Utils::VULN_CODE::CURVE_WRONG;
        ks.vulnerabilityDescription = VULN_NAME.at(Utils::VULN_CODE::ERROR) + "CANNOT DECODE POINT";
        dbm->write_broken_key_csv(ks);
        return;
    }
}

void check_Elgamal_DSA(const DBStruct::pubkey &pk, const shared_ptr<ANALYZER_DBManager> &dbm){
    KeyStatus ks = {
            .version = pk.version,
            .fingerprint = pk.fingerprint
    };

    // Check values exist
    try{
        if(     (pk.pubAlgorithm == OpenPGP::PKA::ID::DSA && (pk.p * pk.q * pk.g * pk.y == 0)) ||
                (pk.pubAlgorithm == OpenPGP::PKA::ID::ELGAMAL && (pk.p * pk.g * pk.y == 0))){
            ks.vulnerabilityCode = VULN_CODE::ERROR;
            ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check DSA/Elgamal values";
            dbm->write_broken_key_csv(ks);
            return;
        }
    }catch (exception &e){
        ks.vulnerabilityCode = VULN_CODE::ERROR;
        ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check DSA/Elgamal values. " + e.what();
        dbm->write_broken_key_csv(ks);
        return;
    }

    // p Prime Test
    try{
        if (!ProbPrime(pk.p, 64)) {
            ks.vulnerabilityCode = VULN_CODE::DSA_ELGAMAL_P_PRIME;
            ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::DSA_ELGAMAL_P_PRIME);
            dbm->write_broken_key_csv(ks);
        }
    }catch (exception &e){
        ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::DSA_ELGAMAL_P_PRIME;
        ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check DSA/Elgamal p - " + e.what();
        dbm->write_broken_key_csv(ks);
    }

    if (pk.pubAlgorithm == PKA::ID::DSA) {

        ELGAMAL_DSA_group_size_check(NumBits(pk.p), ks, dbm);

        // q prime test
        try {
            if (!ProbPrime(pk.q, 64)) {
                ks.vulnerabilityCode = VULN_CODE::DSA_ELGAMAL_Q_PRIME;
                ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::DSA_ELGAMAL_Q_PRIME);
                dbm->write_broken_key_csv(ks);
            }
        } catch (exception &e) {
            ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::DSA_ELGAMAL_Q_PRIME;
            ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check DSA q - " + e.what();
            dbm->write_broken_key_csv(ks);
        }

        ELGAMAL_DSA_subgroup_size_check(NumBits(pk.q), ks, dbm);

        // q divisor of p - 1
        try{
            if ((pk.p - 1) % pk.q != 0){
                ks.vulnerabilityCode = VULN_CODE::DSA_P_1_Q_MULTIPLE;
                ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::DSA_P_1_Q_MULTIPLE);
                dbm->write_broken_key_csv(ks);
            }
        }catch (exception &e){
            ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::DSA_P_1_Q_MULTIPLE;
            ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check DSA q divisor of p-1 - " + e.what();
            dbm->write_broken_key_csv(ks);
        }

        try{
            if (PowerMod(pk.g, pk.q, pk.p) != 1 && pk.g % pk.p != 0){
                ks.vulnerabilityCode = VULN_CODE::DSA_ELGAMAL_G_SUBGROUP;
                ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::DSA_ELGAMAL_G_SUBGROUP);
                dbm->write_broken_key_csv(ks);
            }else{
                ZZ order_other_subgroup = (pk.p - 1) / pk.q;
                if (PowerMod(pk.g, order_other_subgroup, pk.p) == 1){
                    ks.vulnerabilityCode = VULN_CODE::DSA_ELGAMAL_G_SUBGROUP;
                    ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::DSA_ELGAMAL_G_SUBGROUP);
                    dbm->write_broken_key_csv(ks);
                }
            }
        }catch (exception &e){
            ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::DSA_ELGAMAL_G_SUBGROUP;
            ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check DSA g subgroup - " + e.what();
            dbm->write_broken_key_csv(ks);
        }
    }else{
        try{
            if (PowerMod(pk.g, pk.p, pk.p) == 1 && pk.g % pk.p != 0){
                ks.vulnerabilityCode = VULN_CODE::DSA_ELGAMAL_G_SUBGROUP;
                ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::DSA_ELGAMAL_G_SUBGROUP);
                dbm->write_broken_key_csv(ks);
            }
        }catch (exception &e){
            ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::DSA_ELGAMAL_G_SUBGROUP;
            ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check Elgamal g subgroup - " + e.what();
            dbm->write_broken_key_csv(ks);
        }
        // Group size check
        ELGAMAL_DSA_group_size_check(NumBits(pk.p), ks, dbm);
    }


    // g > 1 Check
    try{
        if (pk.g <= 1) {
            ks.vulnerabilityCode = VULN_CODE::DSA_ELGAMAL_G_GT_1;
            ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::DSA_ELGAMAL_G_GT_1);
            dbm->write_broken_key_csv(ks);
        }
    }catch (exception &e){
        ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::DSA_ELGAMAL_G_GT_1;
        ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check DSA/Elgamal g > 1 - " + e.what();
        dbm->write_broken_key_csv(ks);
    }
}

void ELGAMAL_DSA_group_size_check(const unsigned int &p, DBStruct::KeyStatus &ks, const std::shared_ptr<ANALYZER_DBManager> &dbm){
    try{
        if (p <= ELGAMAL_DSA_GROUP_BREAKABLE_SIZE){
              ks.vulnerabilityCode = VULN_CODE::OUTDATED_KEY_SIZE;
              ks.vulnerabilityDescription = "Group breakable size: " + to_string(p);
              dbm->write_broken_key_csv(ks);
        } else if ((p > ELGAMAL_DSA_GROUP_BREAKABLE_SIZE) and (p <= ELGAMAL_DSA_GROUP_UNSAFE_SIZE)){
              ks.vulnerabilityCode = VULN_CODE::OUTDATED_KEY_SIZE;
              ks.vulnerabilityDescription = "Group unsafe size: " + to_string(p);
               dbm->write_broken_key_csv(ks);
        } else if ((p > ELGAMAL_DSA_GROUP_UNSAFE_SIZE) and (p <= ELGAMAL_DSA_GROUP_ADVISED_SIZE)){
              ks.vulnerabilityCode = VULN_CODE::OUTDATED_KEY_SIZE;
              ks.vulnerabilityDescription = "Group below advised size: " + to_string(p);
              dbm->write_broken_key_csv(ks);
        }
    }catch (exception &e){
        ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::OUTDATED_KEY_SIZE;
        ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check DSA p,q size - " + e.what();
        dbm->write_broken_key_csv(ks);
    }
}

void ELGAMAL_DSA_subgroup_size_check(const unsigned int &q, DBStruct::KeyStatus &ks, const std::shared_ptr<ANALYZER_DBManager> &dbm){
        // Subgroup Size Check
    try{
        if (q <= ELGAMAL_DSA_SUBGROUP_BREAKABLE_SIZE) {
            ks.vulnerabilityCode = VULN_CODE::OUTDATED_KEY_SIZE;
            ks.vulnerabilityDescription = "Subgroup breakable size: " + to_string(q);
            dbm->write_broken_key_csv(ks);
        } else if ((q > ELGAMAL_DSA_SUBGROUP_BREAKABLE_SIZE) and (q <= ELGAMAL_DSA_SUBGROUP_UNSAFE_SIZE)) {
            ks.vulnerabilityCode = VULN_CODE::OUTDATED_KEY_SIZE;
            ks.vulnerabilityDescription = "Subgroup unsafe size: " + to_string(q);
            dbm->write_broken_key_csv(ks);
        } else if ((q > ELGAMAL_DSA_SUBGROUP_UNSAFE_SIZE) and (q <= ELGAMAL_DSA_SUBGROUP_ADVISED_SIZE)) {
            ks.vulnerabilityCode = VULN_CODE::OUTDATED_KEY_SIZE;
            ks.vulnerabilityDescription = "Subgroup below advised size: " + to_string(q);
            dbm->write_broken_key_csv(ks);
        }
    }catch (exception &e){
        ks.vulnerabilityCode = VULN_CODE::ERROR + VULN_CODE::OUTDATED_KEY_SIZE;
        ks.vulnerabilityDescription = VULN_NAME.at(VULN_CODE::ERROR) + "check DSA q size - " + e.what();
        dbm->write_broken_key_csv(ks);
    }
}


bool check_signature(const signatures &sign, const shared_ptr<ANALYZER_DBManager> &dbm){
    ZZ signedHash = conv<ZZ>(mpitodec(rawtompi(sign.signedHash)).c_str());
    switch (sign.pubAlgorithm){
        case PKA::ID::RSA_ENCRYPT_ONLY:
        case PKA::ID::RSA_ENCRYPT_OR_SIGN:
        case PKA::ID::RSA_SIGN_ONLY: {
            signedHash = conv<ZZ>(mpitodec(rawtompi(EMSA_PKCS1_v1_5(sign.hashAlgorithm, sign.signedHash, NumBits(sign.pk_n) >> 3))).c_str());
            return PowerMod(sign.s, sign.pk_e, sign.pk_n) == signedHash % sign.pk_n;
        }
        case PKA::ID::ELGAMAL: {
            // 0 < r < p && 0 < s < p-1
            // g^sign.signedHash == y^r * r^s mod p
            ZZ_p::init(sign.pk_p);
            ZZ r = sign.r;
            ZZ s = sign.s;
            ZZ_p g = conv<ZZ_p>(sign.pk_g);
            ZZ_p y = conv<ZZ_p>(sign.pk_y);

            if (r <= 0 || r >= sign.pk_p || s <= 0 || s >= (sign.pk_p - 1)) {
                return false;
            } else {
                return power(g, signedHash) == power(y, r) * power(conv<ZZ_p>(r), s);
            }
        }
        case PKA::ID::DSA: {
            // 0 < r < q && 0 < s < q
            // w = s^-1 mod q
            // u1 = sign.signedHash * w mod q
            // u2 = r * w mod q
            // v = (g^u1 * y^u2 mod p) mod q
            // v == r
            ZZ_p::init(sign.pk_q);
            const ZZ &r = sign.r;
            const ZZ &s = sign.s;

            if (r <= 0 || r >= sign.pk_q || s <= 0 || s >= (sign.pk_q)) {
                return false;
            } else {
                ZZ_p w = power(conv<ZZ_p>(s), -1);
                ZZ_p u1 = conv<ZZ_p>(signedHash) * w;
                ZZ_p u2 = conv<ZZ_p>(r) * w;

                ZZ_p::init(sign.pk_p);
                ZZ_p g = conv<ZZ_p>(sign.pk_g);
                ZZ_p y = conv<ZZ_p>(sign.pk_y);

                ZZ v = conv<ZZ>(power(g, conv<ZZ>(u1)) * power(y, conv<ZZ>(u2))) % sign.pk_q;

                return v == r;
            }
        }
        case PKA::ID::ECDSA: {
            string curve_OID = sign.pk_curve;
            std::transform(curve_OID.begin(), curve_OID.end(), curve_OID.begin(), ::toupper);
            shared_ptr<Elliptic_Curve> curve = make_shared<Elliptic_Curve>(curve_OID);

            EC_point O = EC_point(0, 0, curve);
            EC_point G = EC_point(curve->getG(), curve);
            ZZ n = curve->getOrder();
            ZZ r = sign.r;
            ZZ s = sign.s;

            string flag = mpitohex(zz_to_mpi(sign.pk_p)).substr(0, 2);
            string points = mpitoraw(zz_to_mpi(sign.pk_p)).substr(1);
            EC_point Q;
            if (flag == "04"){
                ZZ x = conv<ZZ>(mpitodec(rawtompi(points.substr(0, points.size() / 2))).c_str());
                ZZ y = conv<ZZ>(mpitodec(rawtompi(points.substr(points.size() / 2))).c_str());
                Q = EC_point(x, y, curve);
            }else if(flag == "40"){
                Q = EC_point(points, curve);
            }else{
                throw runtime_error("Impossible decode point");
            }

            if (r < 1 || r >= n || s < 1 || s >= n){
                return false;
            }
            ZZ z;
            if (NumBits(signedHash) > NumBits(n)){
                z = LeftShift(signedHash, conv<long>(signedHash.size() - n));
            }else{
                z = signedHash;
            }
            ZZ w = PowerMod(s, -1, n);

            ZZ u1 = (z * w) % n;
            ZZ u2 = (r * w) % n;

            EC_point xy = G * u1 + Q * u2;

            if (xy == O){
                return false;
            }

            return r  == conv<ZZ>(xy.getX()) % n;
        }
        case PKA::ID::EdDSA: {
            const string p_k = mpitoraw(zz_to_mpi(sign.pk_p)).substr(1, 32);
            const string msg = sign.signedHash;
            const string Rs = mpitoraw(zz_to_mpi(sign.r));
            const string Ss = mpitoraw(zz_to_mpi(sign.s));

            if (Rs.size() != 32){
                throw runtime_error("Wrong value of Rs in EdDSA");
            }
            if (Ss.size() != 32){
                throw runtime_error("Wrong value of Ss in EdDSA");
            }

            string curve_OID = sign.pk_curve;
            transform(curve_OID.begin(), curve_OID.end(), curve_OID.begin(), ::toupper);
            shared_ptr<Edward_Curve> curve = make_shared<Edward_Curve>(curve_OID);


            ED_point G = ED_point(curve->getG(), curve);
            ED_point P = ED_point(p_k, curve);
            ED_point R = ED_point(Rs, curve);

            ZZ S = ZZ_from_bytes(Ss, 32, ENDIAN::LITTLE);

            if (S >= curve->getQ()){
                return false;
            }
            string hash = Hash::use(Hash::ID::SHA512, Rs + p_k + msg);
            ZZ h = ZZ_from_bytes(hash, hash.size(), ENDIAN::LITTLE) % curve->getQ();
            ED_point sB = G * S;
            ED_point hA = P * h;

            return sB == R + hA;
        }
        default:
            break;
    }
    return false;
}

void analyze_RSA_modulus_common_factor(const shared_ptr<ANALYZER_DBManager> &dbm, const unsigned int &nThreads) {
    fastGCD fgcd = fastGCD(dbm->get_RSA_modulus(), nThreads, CONTEXT.dbsettings.tmp_folder);
    vector<std::string> broken_modulus = fgcd.compute();
    dbm->write_broken_modulus_csv(broken_modulus);
}


}
}
