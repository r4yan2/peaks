#include <iostream>
#include <sys/syslog.h>
#include <cstring>
#include <sstream>

#include "DBManager.h"
#include "utils.h"


using namespace std;
using namespace ANALYZER_DBStruct;
using namespace OpenPGP;
using namespace NTL;


// Database connector initialization
ANALYZER_DBManager::ANALYZER_DBManager(const DBSettings & settings_, const AnalyzerFolders & folders_):DBManager(settings_) {
    folders = folders_;
    prepare_queries();
}

void ANALYZER_DBManager::prepare_queries(){
    //con->createStatement()->execute("set sql_log_bin = 0;");
    //con->createStatement()->execute("set foreign_key_checks = 0;");

    get_repeated_r_stmt = prepare_query("SELECT id from "
                      "Signatures where (pubAlgorithm = 16 or pubAlgorithm = 17 or pubAlgorithm = 18) and id not in "
                      "(SELECT signature_id from SignatureStatus WHERE vulnerabilityCode = 24) and is_analyzed = 1 GROUP by "
                      "issuingKeyId, r having count(r) > 1");
    get_analyzable_pubkey_stmt = prepare_query("SELECT * FROM Pubkey WHERE "
            "is_analyzed = 0 LIMIT ?;");
    get_analyzable_signature_stmt = prepare_query("SELECT * FROM Signatures "
            "INNER JOIN Pubkey ON Signatures.issuingFingerprint = Pubkey.fingerprint "
            "LEFT JOIN KeyStatus ON KeyStatus.fingerprint = Pubkey.fingerprint and KeyStatus.version = Pubkey.version "
            "WHERE Signatures.is_analyzed = 0 and Pubkey.is_analyzed = 1 LIMIT ?;");
    get_RSA_modulo_list_stmt = prepare_query("SELECT DISTINCT n FROM Pubkey "
            "WHERE pubAlgorithm <= 3 and n != \"\" and (version, fingerprint) not in "
            "(SELECT version, fingerprint from KeyStatus WHERE vulnerabilityCode = 4);");

    get_MPI_pubkey_stmt = prepare_query("SELECT e, n, p, q, g, y, curveOID "
            "FROM Pubkey AS p INNER JOIN KeyStatus AS ks WHERE p.version = (?) and p.fingerprint = unhex(?) "
            "and (vulnerabilityCode < 7 or vulnerabilityCode = 10);");

    commit_stmt = prepare_query("COMMIT");

    set_pubkey_analyzed_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
            "' IGNORE INTO TABLE tmp_analyzer_pk FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
            "LINES STARTING BY '.' TERMINATED BY '\\n' "
            "(version,@hexfingerprint) SET fingerprint = UNHEX(@hexfingerprint);");

    set_analyzed_signature_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
            "' IGNORE INTO TABLE tmp_analyzer_s FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
            "LINES STARTING BY '.' TERMINATED BY '\\n' (signature_id);");

    insert_broken_key_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
            "' IGNORE INTO TABLE KeyStatus FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
            " LINES STARTING BY '.' TERMINATED BY '\\n' "
            "(version,@hexfingerprint,vulnerabilityCode,vulnerabilityDescription) "
            "SET fingerprint = UNHEX(@hexfingerprint);");

    insert_broken_modulus_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
            "' IGNORE INTO TABLE tmp_analyzer_mod FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES STARTING BY '.' "
            "TERMINATED BY '\\n' (@hexn) SET RSA_modulus = UNHEX(@hexn);");

    insert_broken_signature_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
            "' IGNORE INTO TABLE SignatureStatus FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
            "LINES STARTING BY '.' TERMINATED BY '\\n' "
            "(signature_id,vulnerabilityCode,vulnerabilityDescription);");

    insert_repeated_r_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
            "' IGNORE INTO TABLE tmp_analyzer_repR FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES STARTING BY '.' "
            "TERMINATED BY '\\n';");

}

vector<pubkey> ANALYZER_DBManager::get_pubkey(const unsigned long &l) {
    vector<pubkey> pk;
    commit_stmt->execute();
    get_analyzable_pubkey_stmt->setString(1, to_string(l));
    std::unique_ptr<DBResult> result = get_analyzable_pubkey_stmt->execute();
    while (result->next()) {
        try {
            pubkey temp_pk = {
                    version : result->getUInt("version"),
                    fingerprint : result->getString("fingerprint"),
                    pubAlgorithm : result->getInt("pubAlgorithm"),
                    e : ZZ(0),
                    n : ZZ(0),
                    p : ZZ(0),
                    q : ZZ(0),
                    g : ZZ(0),
                    y : ZZ(0),
                    curve : result->getString("curveOID")
            };
            switch (temp_pk.pubAlgorithm) {
                case PKA::ID::RSA_ENCRYPT_ONLY:
                case PKA::ID::RSA_SIGN_ONLY:
                case PKA::ID::RSA_ENCRYPT_OR_SIGN:
                    try {
                        temp_pk.e = conv<ZZ>(mpitodec(rawtompi(result->getString("e"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost RSA key e value" << endl;
                    }
                    try {
                        temp_pk.n = conv<ZZ>(mpitodec(rawtompi(result->getString("n"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost RSA key n value" << endl;
                    }
                    break;
                case PKA::ID::DSA:
                    try {
                        temp_pk.p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost DSA key p value" << endl;
                    }
                    try {
                        temp_pk.q = conv<ZZ>(mpitodec(rawtompi(result->getString("q"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost DSA key q value" << endl;
                    }
                    try {
                        temp_pk.g = conv<ZZ>(mpitodec(rawtompi(result->getString("g"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost DSA key g value" << endl;
                    }
                    try {
                        temp_pk.y = conv<ZZ>(mpitodec(rawtompi(result->getString("y"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost DSA key y value" << endl;
                    }
                    break;
                case PKA::ID::ELGAMAL:
                case PKA::ID::RESERVED_ELGAMAL:
                    try {
                        temp_pk.p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost ELGAMAL key p value" << endl;
                    }
                    try {
                        temp_pk.g = conv<ZZ>(mpitodec(rawtompi(result->getString("g"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost ELGAMAL key g value" << endl;
                    }
                    try {
                        temp_pk.y = conv<ZZ>(mpitodec(rawtompi(result->getString("y"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost ELGAMAL key y value" << endl;
                    }
                    break;
                case PKA::ID::ECDSA:
                case PKA::ID::EdDSA:
                case PKA::ID::ECDH:
                    try {
                        temp_pk.p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost CURVE key y value" << endl;
                    }
                    break;
                default:
                    break;
            }
            pk.push_back(temp_pk);
        } catch (exception &e){
            cerr << "Impossible to get key due to: " << e.what() << endl;
        }
    }
    return pk;
}

std::vector<ANALYZER_DBStruct::signatures> ANALYZER_DBManager::get_signatures(const unsigned long &l) {
    commit_stmt->execute();
    vector<signatures> ss;
    get_analyzable_signature_stmt->setString(1, to_string(l));
    std::unique_ptr<DBResult> result = get_analyzable_signature_stmt->execute();
    while (result->next()) {
        try {
            signatures temp_s = {
                    id : result->getUInt("id"),
                    pubAlgorithm : result->getUInt("pubAlgorithm"),
                    hashAlgorithm : result->getUInt("hashAlgorithm"),
                    version : result->getUInt("version"),
                    issuingFingerprint : result->getString("issuingFingerprint"),
                    signedFingerprint : result->getString("signedFingerprint"),
                    r : ZZ(0),
                    s : ZZ(0),
                    hashHeader : result->getString("hashHeader"),
                    signedHash : result->getString("signedHash"),
                    isExportable : result->getBoolean("isExportable"),
                    pk_e : ZZ(0),
                    pk_n : ZZ(0),
                    pk_p : ZZ(0),
                    pk_q : ZZ(0),
                    pk_g : ZZ(0),
                    pk_y : ZZ(0),
                    pk_curve : result->getString("curveOID"),
                    pk_status : result->getUInt("vulnerabilityCode"),
            };
            try {
                temp_s.s = conv<ZZ>(mpitodec(rawtompi(result->getString("s"))).c_str());
            } catch (exception &e) {
                cerr << "Lost Signature s value" << endl;
            }
            if (!PKA::is_RSA(temp_s.pubAlgorithm)) {
                try {
                    temp_s.r = conv<ZZ>(mpitodec(rawtompi(result->getString("r"))).c_str());
                } catch (exception &e) {
                    cerr << "Lost Signature r value" << endl;
                }
            }
            switch (temp_s.pubAlgorithm) {
                case PKA::ID::RSA_ENCRYPT_ONLY:
                case PKA::ID::RSA_SIGN_ONLY:
                case PKA::ID::RSA_ENCRYPT_OR_SIGN:
                    try {
                        temp_s.pk_e = conv<ZZ>(mpitodec(rawtompi(result->getString("e"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost RSA key e value" << endl;
                    }
                    try {
                        temp_s.pk_n = conv<ZZ>(mpitodec(rawtompi(result->getString("n"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost RSA key n value" << endl;
                    }
                    break;
                case PKA::ID::DSA:
                    try {
                        temp_s.pk_p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost DSA key p value" << endl;
                    }
                    try {
                        temp_s.pk_q = conv<ZZ>(mpitodec(rawtompi(result->getString("q"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost DSA key q value" << endl;
                    }
                    try {
                        temp_s.pk_g = conv<ZZ>(mpitodec(rawtompi(result->getString("g"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost DSA key g value" << endl;
                    }
                    try {
                        temp_s.pk_y = conv<ZZ>(mpitodec(rawtompi(result->getString("y"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost DSA key y value" << endl;
                    }
                    break;
                case PKA::ID::ELGAMAL:
                case PKA::ID::RESERVED_ELGAMAL:
                    try {
                        temp_s.pk_p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost ELGAMAL key p value" << endl;
                    }
                    try {
                        temp_s.pk_g = conv<ZZ>(mpitodec(rawtompi(result->getString("g"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost ELGAMAL key g value" << endl;
                    }
                    try {
                        temp_s.pk_y = conv<ZZ>(mpitodec(rawtompi(result->getString("y"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost ELGAMAL key y value" << endl;
                    }
                    break;
                case PKA::ID::ECDSA:
                case PKA::ID::EdDSA:
                case PKA::ID::ECDH:
                    try {
                        temp_s.pk_p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        cerr << "Lost CURVE key y value" << endl;
                    }
                    break;
                default:
                    break;
            }
            ss.push_back(temp_s);

        } catch (exception &e) {
            cerr << "Impossible to get signature due to: " << e.what() << endl;
        }
    }
    return ss;
}

vector<ZZ> ANALYZER_DBManager::get_RSA_modulus(){
    vector<ZZ> n_list;
    unique_ptr<DBResult> result = get_RSA_modulo_list_stmt->execute();
    while(result->next()){
        n_list.emplace_back(conv<ZZ>(mpitodec(rawtompi(result->getString("n"))).c_str()));
    }
    return n_list;
}

void ANALYZER_DBManager::write_analyzed_pk_csv(const ANALYZER_DBStruct::pubkey &pk){
    try{
        ostream &f = file_list.at(ANALYZER_Utils::ANALYZED_PUBKEY);
        f << '.' << '"' << to_string(pk.version) << "\",";
        f << '"' << hexlify(pk.fingerprint) << "\",";
        f << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_analyzed_pk_csv FAILED, the key will result ANALYZABLE in the database! - %s",
                         e.what());
    }
}

void ANALYZER_DBManager::write_analyzed_sign_csv(const ANALYZER_DBStruct::signatures &s){
    try{
        ostream &f = file_list.at(ANALYZER_Utils::ANALYZED_SIGNATURE);
        f << '.' << '"' << to_string(s.id) << "\"";
        f << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_analyzed_sign_csv FAILED, the signature will result ANALYZABLE in the database! - %s",
                          e.what());
    }
}

void ANALYZER_DBManager::write_broken_modulus_csv(const std::vector<std::string> &broken_modulus) {
    try{
        ofstream f = ofstream(ANALYZER_Utils::get_file_name(folders.analyzer_tmp_folder, ANALYZER_Utils::BROKEN_MODULUS, this_thread::get_id()), ios_base::app);
        for (const auto &n: broken_modulus){
            f << '.' << '"' << n << '"' << "\n";
        }
        f.close();
    } catch (exception &e){
        syslog(LOG_CRIT, "write_broken_modulus_csv FAILED, the modulo will result not broken in the database! - %s",
                          e.what());
    }
}

void ANALYZER_DBManager::write_broken_key_csv(const ANALYZER_DBStruct::KeyStatus &ks) {
    try{
        ofstream &f = file_list.at(ANALYZER_Utils::BROKEN_PUBKEY);
        f << '.' << '"' << ks.version << "\",";
        f << '"' << hexlify(ks.fingerprint) << "\",";
        f << '"' << ks.vulnerabilityCode << "\",";
        f << '"' << ks.vulnerabilityDescription << "\"";
        f << "\n";
    } catch (exception &e){
        syslog(LOG_CRIT, "write_broken_key_csv FAILED, the key will result not broken in the database! - %s",
                          e.what());
    }
}

void ANALYZER_DBManager::write_broken_signature_csv(const ANALYZER_DBStruct::SignatureStatus &ss) {
    try{
        ofstream &f = file_list.at(ANALYZER_Utils::BROKEN_SIGNATURE);
        f << '.' << '"' << ss.signature_id << "\",";
        f << '"' << ss.vulnerabilityCode << "\",";
        f << '"' << ss.vulnerabilityDescription << "\"";
        f << "\n";
    } catch (exception &e){
	    string tmp = e.what();
        syslog(LOG_CRIT, "write_broken_signature_csv FAILED, the signature will result not broken in the database! - %s",
                          e.what());
    }
}

void ANALYZER_DBManager::write_repeated_r_csv() {
    try{
        std::unique_ptr<DBResult> result = get_repeated_r_stmt->execute();
        ofstream f = ofstream(ANALYZER_Utils::get_file_name(folders.analyzer_tmp_folder, ANALYZER_Utils::REPEATED_R, this_thread::get_id()), ios_base::app);
        while (result->next()) {
            f << '.' << '"' << result->getInt("id") << '"' << "\n";
        }
        f.close();
    } catch (exception &e){
        syslog(LOG_CRIT, "write_repeated_r_csv FAILED, the signature will result not broken in the database! - %s",
                          e.what());
    }
}

void ANALYZER_DBManager::insertCSV(const vector<string> &files, const unsigned int &table){
    switch (table){
        case ANALYZER_Utils::ANALYZED_PUBKEY:
            for (const auto &f: files){
                try{
                    execute_query("CREATE TABLE tmp_analyzer_pk (version tinyint, "
                               "fingerprint binary(20), analyzed tinyint, PRIMARY KEY (version, fingerprint)) ENGINE=MEMORY;");
                    execute_query(set_pubkey_analyzed_stmt.first + f + set_pubkey_analyzed_stmt.second);
                    execute_query("UPDATE Pubkey INNER JOIN tmp_analyzer_pk ON "
                               "tmp_analyzer_pk.version = Pubkey.version AND tmp_analyzer_pk.fingerprint = Pubkey.fingerprint "
                               "SET Pubkey.is_analyzed = 1;");
                    execute_query("DROP TABLE tmp_analyzer_pk;");
                }catch (exception &e){
                    syslog(LOG_CRIT, "set_pubkey_analyzed_stmt FAILED, the key will result ANALYZABLE in the database! - %s",
                                      e.what());
                    ANALYZER_Utils::put_in_error(folders.analyzer_error_folder, f, ANALYZER_Utils::ANALYZED_PUBKEY);
                }
            }
            break;
        case ANALYZER_Utils::ANALYZED_SIGNATURE:
            for (const auto &f: files){
                try{
                    execute_query("CREATE TABLE tmp_analyzer_s (signature_id int(10), "
                               "PRIMARY KEY (signature_id)) ENGINE=MEMORY;");
                    execute_query(set_analyzed_signature_stmt.first + f + set_analyzed_signature_stmt.second);
                    execute_query("UPDATE Signatures INNER JOIN tmp_analyzer_s ON "
                               "tmp_analyzer_s.signature_id = Signatures.id SET Signatures.is_analyzed = 1;");
                    execute_query("DROP TABLE tmp_analyzer_s;");
                }catch (exception &e){
                    syslog(LOG_CRIT, "set_analyzed_signature_stmt FAILED, the signature will result ANALYZABLE in the database! - %s",
                                      e.what());
                    ANALYZER_Utils::put_in_error(folders.analyzer_error_folder, f, ANALYZER_Utils::ANALYZED_SIGNATURE);
                }
            }
            break;
        case ANALYZER_Utils::BROKEN_PUBKEY:
            for (const auto &f: files){
                try{
                    execute_query(insert_broken_key_stmt.first + f + insert_broken_key_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_broken_key_stmt FAILED, the key will result not broken in the database! - %s",
                                      e.what());
                    ANALYZER_Utils::put_in_error(folders.analyzer_error_folder, f, ANALYZER_Utils::BROKEN_PUBKEY);
                }
            }
            break;
        case ANALYZER_Utils::BROKEN_MODULUS:
            for (const auto &f: files){
                try{
                    execute_query("CREATE TABLE tmp_analyzer_mod (RSA_modulus blob, "
                               "PRIMARY KEY (RSA_modulus(767)));");
                    auto insert_keystatus_stmt = prepare_query("INSERT IGNORE INTO "
                               "KeyStatus SELECT version, fingerprint, ?, ? FROM Pubkey WHERE n in (SELECT * FROM tmp_analyzer_mod)");
                    execute_query(insert_broken_modulus_stmt.first + f + insert_broken_modulus_stmt.second);
                    insert_keystatus_stmt->setInt(1, ANALYZER_Utils::VULN_CODE::RSA_COMMON_FACTOR);
                    insert_keystatus_stmt->setString(2, ANALYZER_Utils::VULN_NAME.at(ANALYZER_Utils::VULN_CODE::RSA_COMMON_FACTOR));
                    insert_keystatus_stmt->execute();
                    execute_query("DROP TABLE tmp_analyzer_mod;");
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_broken_modulus_stmt FAILED, the key will result not broken in the database! - %s",
                                      e.what());
                    ANALYZER_Utils::put_in_error(folders.analyzer_error_folder, f, ANALYZER_Utils::BROKEN_MODULUS);
                }
            }
            break;
        case ANALYZER_Utils::BROKEN_SIGNATURE:
            for (const auto &f: files){
                try{
                    execute_query(insert_broken_signature_stmt.first + f + insert_broken_signature_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_broken_signature_stmt FAILED, the signature will result not broken in the database! - %s",
                                      e.what());
                    ANALYZER_Utils::put_in_error(folders.analyzer_error_folder, f, ANALYZER_Utils::BROKEN_SIGNATURE);
                }
            }
            break;
        case ANALYZER_Utils::REPEATED_R:
            for (const auto &f: files){
                try{
                    execute_query("CREATE TABLE tmp_analyzer_repR (id int(10), "
                               "PRIMARY KEY(id)) ENGINE=MEMORY;");
                    auto insert_signatureStatus_stmt = prepare_query("INSERT IGNORE "
                               "INTO SignatureStatus SELECT id, ?, ? FROM tmp_analyzer_repR;");
                    execute_query(insert_repeated_r_stmt.first + f + insert_repeated_r_stmt.second);
                    insert_signatureStatus_stmt->setInt(1, ANALYZER_Utils::VULN_CODE::SIGNATURE_REPEATED_R);
                    insert_signatureStatus_stmt->setString(2, ANALYZER_Utils::VULN_NAME.at(ANALYZER_Utils::VULN_CODE::SIGNATURE_REPEATED_R));
                    insert_signatureStatus_stmt->execute();
                    execute_query("DROP TABLE tmp_analyzer_repR;");
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_repeated_r_stmt FAILED, the signature will result not broken in the database! - %s",
                                      e.what());
                    ANALYZER_Utils::put_in_error(folders.analyzer_error_folder, f, ANALYZER_Utils::REPEATED_R);
                }
            }
            break;
        default:
            syslog(LOG_WARNING, "Table not recognized during CSV insertion");
    }

    // Delete inserted file
    for (const auto &f: files){
        try{
            remove(f.c_str());
        }catch (exception &e){
            syslog(LOG_CRIT, "Error during deletion of files. The file will remaining in the temp folder. - %s",
                              e.what());
        }
    }
}

void ANALYZER_DBManager::open_pubkey_files() {
    ANALYZER_DBManager::file_list.insert(std::pair<unsigned int, ofstream>(ANALYZER_Utils::ANALYZED_PUBKEY,
                         ofstream(ANALYZER_Utils::get_file_name(folders.analyzer_tmp_folder, ANALYZER_Utils::ANALYZED_PUBKEY, this_thread::get_id()), ios_base::app)));
    ANALYZER_DBManager::file_list.insert(std::pair<unsigned int, ofstream>(ANALYZER_Utils::BROKEN_PUBKEY,
                         ofstream(ANALYZER_Utils::get_file_name(folders.analyzer_tmp_folder, ANALYZER_Utils::BROKEN_PUBKEY, this_thread::get_id()), ios_base::app)));
}

void ANALYZER_DBManager::open_signatures_files() {
    for (auto & sig: {
            ANALYZER_Utils::ANALYZED_SIGNATURE, 
            ANALYZER_Utils::BROKEN_SIGNATURE
            }){
    ANALYZER_DBManager::file_list.insert(std::pair<unsigned int, ofstream>(sig, ofstream(ANALYZER_Utils::get_file_name(folders.analyzer_tmp_folder, sig, this_thread::get_id()), ios_base::app)));
    }
}

ANALYZER_DBManager::~ANALYZER_DBManager(){
    for (auto &it: file_list){
        if (it.second.is_open()){
            it.second.close();
        }
    }
}
