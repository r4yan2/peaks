#include <iostream>
#include <sys/syslog.h>
#include <cstring>
#include <sstream>

#include "DBManager.h"
#include <common/utils.h>
#include <common/config.h>

using namespace std;
using namespace OpenPGP;
using namespace NTL;

using namespace peaks::common::DBStruct;
namespace peaks{
namespace analyzer{

// Database connector initialization
ANALYZER_DBManager::ANALYZER_DBManager():DBManager() {
    check_sql_mode();
    connect_schema();
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
            "LINES TERMINATED BY '\\n' "
            "(version,@hexfingerprint) SET fingerprint = UNHEX(@hexfingerprint);");

    set_analyzed_signature_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
            "' IGNORE INTO TABLE tmp_analyzer_s FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
            "LINES TERMINATED BY '\\n' (signature_id);");

    insert_broken_key_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
            "' IGNORE INTO TABLE KeyStatus FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
            " LINES TERMINATED BY '\\n' "
            "(version,@hexfingerprint,vulnerabilityCode,vulnerabilityDescription) "
            "SET fingerprint = UNHEX(@hexfingerprint);");

    insert_broken_modulus_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
            "' IGNORE INTO TABLE tmp_analyzer_mod FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES "
            "TERMINATED BY '\\n' (@hexn) SET RSA_modulus = UNHEX(@hexn);");

    insert_broken_signature_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
            "' IGNORE INTO TABLE SignatureStatus FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
            "LINES TERMINATED BY '\\n' "
            "(signature_id,vulnerabilityCode,vulnerabilityDescription);");

    insert_repeated_r_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
            "' IGNORE INTO TABLE tmp_analyzer_repR FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES "
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
                        syslog(LOG_DEBUG, "Lost RSA key e value");
                    }
                    try {
                        temp_pk.n = conv<ZZ>(mpitodec(rawtompi(result->getString("n"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost RSA key n value");
                    }
                    break;
                case PKA::ID::DSA:
                    try {
                        temp_pk.p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost DSA key p value");
                    }
                    try {
                        temp_pk.q = conv<ZZ>(mpitodec(rawtompi(result->getString("q"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost DSA key q value");
                    }
                    try {
                        temp_pk.g = conv<ZZ>(mpitodec(rawtompi(result->getString("g"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost DSA key g value");
                    }
                    try {
                        temp_pk.y = conv<ZZ>(mpitodec(rawtompi(result->getString("y"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost DSA key y value");
                    }
                    break;
                case PKA::ID::ELGAMAL:
                //case PKA::ID::RESERVED_ELGAMAL:
                    try {
                        temp_pk.p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost ELGAMAL key p value");
                    }
                    try {
                        temp_pk.g = conv<ZZ>(mpitodec(rawtompi(result->getString("g"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost ELGAMAL key g value");
                    }
                    try {
                        temp_pk.y = conv<ZZ>(mpitodec(rawtompi(result->getString("y"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost ELGAMAL key y value");
                    }
                    break;
                case PKA::ID::ECDSA:
                case PKA::ID::EdDSA:
                case PKA::ID::ECDH:
                    try {
                        temp_pk.p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost CURVE key y value");
                    }
                    break;
                default:
                    break;
            }
            pk.push_back(temp_pk);
        } catch (exception &e){
            syslog(LOG_DEBUG, "Impossible to get key due to: %s", e.what());
        }
    }
    return pk;
}

std::vector<DBStruct::signatures> ANALYZER_DBManager::get_signatures(const unsigned long &l) {
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
                syslog(LOG_DEBUG, "Lost Signature s value");
            }
            if (!PKA::is_RSA(temp_s.pubAlgorithm)) {
                try {
                    temp_s.r = conv<ZZ>(mpitodec(rawtompi(result->getString("r"))).c_str());
                } catch (exception &e) {
                    syslog(LOG_DEBUG, "Lost Signature r value");
                }
            }
            switch (temp_s.pubAlgorithm) {
                case PKA::ID::RSA_ENCRYPT_ONLY:
                case PKA::ID::RSA_SIGN_ONLY:
                case PKA::ID::RSA_ENCRYPT_OR_SIGN:
                    try {
                        temp_s.pk_e = conv<ZZ>(mpitodec(rawtompi(result->getString("e"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost RSA key e value");
                    }
                    try {
                        temp_s.pk_n = conv<ZZ>(mpitodec(rawtompi(result->getString("n"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost RSA key n value");
                    }
                    break;
                case PKA::ID::DSA:
                    try {
                        temp_s.pk_p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost DSA key p value");
                    }
                    try {
                        temp_s.pk_q = conv<ZZ>(mpitodec(rawtompi(result->getString("q"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost DSA key q value");
                    }
                    try {
                        temp_s.pk_g = conv<ZZ>(mpitodec(rawtompi(result->getString("g"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost DSA key g value");
                    }
                    try {
                        temp_s.pk_y = conv<ZZ>(mpitodec(rawtompi(result->getString("y"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost DSA key y value");
                    }
                    break;
                case PKA::ID::ELGAMAL:
                //case PKA::ID::RESERVED_ELGAMAL:
                    try {
                        temp_s.pk_p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost ELGAMAL key p value");
                    }
                    try {
                        temp_s.pk_g = conv<ZZ>(mpitodec(rawtompi(result->getString("g"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost ELGAMAL key g value");
                    }
                    try {
                        temp_s.pk_y = conv<ZZ>(mpitodec(rawtompi(result->getString("y"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost ELGAMAL key y value");
                    }
                    break;
                case PKA::ID::ECDSA:
                case PKA::ID::EdDSA:
                case PKA::ID::ECDH:
                    try {
                        temp_s.pk_p = conv<ZZ>(mpitodec(rawtompi(result->getString("p"))).c_str());
                    } catch (exception &e) {
                        syslog(LOG_DEBUG, "Lost CURVE key y value");
                    }
                    break;
                default:
                    break;
            }
            ss.push_back(temp_s);

        } catch (exception &e) {
            syslog(LOG_DEBUG, "Impossible to get signature due to: %s", e.what());
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

void ANALYZER_DBManager::write_analyzed_pk_csv(const DBStruct::pubkey &pk){
    try{
        ostringstream f;
        f << '"' << to_string(pk.version) << "\",";
        f << '"' << hexlify(pk.fingerprint) << "\",";
        f << "\n";
        file_list.at(Utils::ANALYZER_FILES::ANALYZED_PUBKEY)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_analyzed_pk_csv FAILED, the key will result ANALYZABLE in the database! - %s",
                         e.what());
    }
}

void ANALYZER_DBManager::write_analyzed_sign_csv(const DBStruct::signatures &s){
    try{
        ostringstream f;
        f << '"' << to_string(s.id) << "\"";
        f << "\n";
        file_list.at(Utils::ANALYZER_FILES::ANALYZED_SIGNATURE)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_analyzed_sign_csv FAILED, the signature will result ANALYZABLE in the database! - %s",
                          e.what());
    }
}

void ANALYZER_DBManager::write_broken_modulus_csv(const std::vector<std::string> &broken_modulus) {
    try{
        ostringstream f;
        for (const auto &n: broken_modulus){
            f << '"' << n << '"' << "\n";
        }
        file_list.at(Utils::ANALYZER_FILES::BROKEN_MODULUS)->write(f.str());
    } catch (exception &e){
        syslog(LOG_CRIT, "write_broken_modulus_csv FAILED, the modulo will result not broken in the database! - %s",
                          e.what());
    }
}

void ANALYZER_DBManager::write_broken_key_csv(const DBStruct::KeyStatus &ks) {
    try{
        ostringstream f;
        f << '"' << ks.version << "\",";
        f << '"' << hexlify(ks.fingerprint) << "\",";
        f << '"' << ks.vulnerabilityCode << "\",";
        f << '"' << ks.vulnerabilityDescription << "\"";
        f << "\n";
        file_list.at(Utils::ANALYZER_FILES::BROKEN_PUBKEY)->write(f.str());
    } catch (exception &e){
        syslog(LOG_CRIT, "write_broken_key_csv FAILED, the key will result not broken in the database! - %s",
                          e.what());
    }
}

void ANALYZER_DBManager::write_broken_signature_csv(const DBStruct::SignatureStatus &ss) {
    try{ 
        ostringstream f;
        f << '"' << ss.signature_id << "\",";
        f << '"' << ss.vulnerabilityCode << "\",";
        f << '"' << ss.vulnerabilityDescription << "\"";
        f << "\n";
        file_list.at(Utils::ANALYZER_FILES::BROKEN_SIGNATURE)->write(f.str());
    } catch (exception &e){
	    string tmp = e.what();
        syslog(LOG_CRIT, "write_broken_signature_csv FAILED, the signature will result not broken in the database! - %s",
                          e.what());
    }
}

void ANALYZER_DBManager::write_repeated_r_csv() {
    try{
        std::unique_ptr<DBResult> result = get_repeated_r_stmt->execute();
        ostringstream f;
        while (result->next()) {
            f << '"' << result->getInt("id") << '"' << "\n";
        }
        file_list.at(Utils::ANALYZER_FILES::REPEATED_R)->write(f.str());
    } catch (exception &e){
        syslog(LOG_CRIT, "write_repeated_r_csv FAILED, the signature will result not broken in the database! - %s",
                          e.what());
    }
}

void ANALYZER_DBManager::insertCSV(const unsigned int &table){
    std::string f = file_list.at(table)->get_name();
    file_list.at(table)->close();
    switch (table){
        case Utils::ANALYZER_FILES::ANALYZED_PUBKEY:
            try{
                execute_query("CREATE TEMPORARY TABLE tmp_analyzer_pk (version tinyint, "
                           "fingerprint binary(20), analyzed tinyint, PRIMARY KEY (version, fingerprint));");
                execute_query(set_pubkey_analyzed_stmt.first + f + set_pubkey_analyzed_stmt.second);
                execute_query("UPDATE Pubkey INNER JOIN tmp_analyzer_pk ON "
                           "tmp_analyzer_pk.version = Pubkey.version AND tmp_analyzer_pk.fingerprint = Pubkey.fingerprint "
                           "SET Pubkey.is_analyzed = 1;");
                execute_query("DROP TEMPORARY TABLE tmp_analyzer_pk;");
            }catch (exception &e){
                syslog(LOG_CRIT, "set_pubkey_analyzed_stmt FAILED, the key will result ANALYZABLE in the database! - %s",
                                  e.what());
                Utils::put_in_error(CONTEXT.dbsettings.error_folder, f, Utils::ANALYZER_FILES::ANALYZED_PUBKEY);
            }
            break;
        case Utils::ANALYZER_FILES::ANALYZED_SIGNATURE:
            try{
                execute_query("CREATE TEMPORARY TABLE tmp_analyzer_s (signature_id int(10), "
                           "PRIMARY KEY (signature_id));");
                execute_query(set_analyzed_signature_stmt.first + f + set_analyzed_signature_stmt.second);
                execute_query("UPDATE Signatures INNER JOIN tmp_analyzer_s ON "
                           "tmp_analyzer_s.signature_id = Signatures.id SET Signatures.is_analyzed = 1;");
                execute_query("DROP TEMPORARY TABLE tmp_analyzer_s;");
            }catch (exception &e){
                syslog(LOG_CRIT, "set_analyzed_signature_stmt FAILED, the signature will result ANALYZABLE in the database! - %s",
                                  e.what());
                Utils::put_in_error(CONTEXT.dbsettings.error_folder, f, Utils::ANALYZER_FILES::ANALYZED_SIGNATURE);
            }
            break;
        case Utils::ANALYZER_FILES::BROKEN_PUBKEY:
            try{
                execute_query(insert_broken_key_stmt.first + f + insert_broken_key_stmt.second);
            }catch (exception &e){
                syslog(LOG_CRIT, "insert_broken_key_stmt FAILED, the key will result not broken in the database! - %s",
                                  e.what());
                Utils::put_in_error(CONTEXT.dbsettings.error_folder, f, Utils::ANALYZER_FILES::BROKEN_PUBKEY);
            }
            break;
        case Utils::ANALYZER_FILES::BROKEN_MODULUS:
            try{
                execute_query("CREATE TEMPORARY TABLE tmp_analyzer_mod (RSA_modulus blob, "
                           "PRIMARY KEY (RSA_modulus(767)));");
                auto insert_keystatus_stmt = prepare_query("INSERT IGNORE INTO "
                           "KeyStatus SELECT version, fingerprint, ?, ? FROM Pubkey WHERE n in (SELECT * FROM tmp_analyzer_mod)");
                execute_query(insert_broken_modulus_stmt.first + f + insert_broken_modulus_stmt.second);
                insert_keystatus_stmt->setInt(1, Utils::VULN_CODE::RSA_COMMON_FACTOR);
                insert_keystatus_stmt->setString(2, Utils::VULN_NAME.at(Utils::VULN_CODE::RSA_COMMON_FACTOR));
                insert_keystatus_stmt->execute();
                execute_query("DROP TEMPORARY TABLE tmp_analyzer_mod;");
            }catch (exception &e){
                syslog(LOG_CRIT, "insert_broken_modulus_stmt FAILED, the key will result not broken in the database! - %s",
                                  e.what());
                Utils::put_in_error(CONTEXT.dbsettings.error_folder, f, Utils::ANALYZER_FILES::BROKEN_MODULUS);
            }
            break;
        case Utils::ANALYZER_FILES::BROKEN_SIGNATURE:
            try{
                execute_query(insert_broken_signature_stmt.first + f + insert_broken_signature_stmt.second);
            }catch (exception &e){
                syslog(LOG_CRIT, "insert_broken_signature_stmt FAILED, the signature will result not broken in the database! - %s",
                                  e.what());
                Utils::put_in_error(CONTEXT.dbsettings.error_folder, f, Utils::ANALYZER_FILES::BROKEN_SIGNATURE);
            }
            break;
        case Utils::ANALYZER_FILES::REPEATED_R:
            try{
                execute_query("CREATE TEMPORARY TABLE tmp_analyzer_repR (id int(10), "
                           "PRIMARY KEY(id));");
                auto insert_signatureStatus_stmt = prepare_query("INSERT IGNORE "
                           "INTO SignatureStatus SELECT id, ?, ? FROM tmp_analyzer_repR;");
                execute_query(insert_repeated_r_stmt.first + f + insert_repeated_r_stmt.second);
                insert_signatureStatus_stmt->setInt(1, Utils::VULN_CODE::SIGNATURE_REPEATED_R);
                insert_signatureStatus_stmt->setString(2, Utils::VULN_NAME.at(Utils::VULN_CODE::SIGNATURE_REPEATED_R));
                insert_signatureStatus_stmt->execute();
                execute_query("DROP TEMPORARY TABLE tmp_analyzer_repR;");
            }catch (exception &e){
                syslog(LOG_CRIT, "insert_repeated_r_stmt FAILED, the signature will result not broken in the database! - %s",
                                  e.what());
                Utils::put_in_error(CONTEXT.dbsettings.error_folder, f, Utils::ANALYZER_FILES::REPEATED_R);
            }
            break;
        default:
            syslog(LOG_WARNING, "Table not recognized during CSV insertion");
    }

    // Delete inserted file
    try{
        remove(f.c_str());
    }catch (exception &e){
        syslog(LOG_CRIT, "Error during deletion of files. The file will remaining in the temp folder. - %s",
                          e.what());
    }
}

void ANALYZER_DBManager::open_files() {
    for (const auto &it: Utils::ANALYZER_FILES::FILENAME)
		ANALYZER_DBManager::file_list[it.first] = make_shared<SynchronizedFile>(Utils::get_file_name(CONTEXT.dbsettings.tmp_folder, it.second));
}

ANALYZER_DBManager::~ANALYZER_DBManager(){
    for (const auto &f: file_list)
        f.second->close();
}

 
}
}
