
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <syslog.h>
#include <common/includes.h>

// Local files includes
#include "db.h"
#include "utils.h"

// Include MySQL connector
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <mysql_connection.h>
#include <common/includes.h>
#include <PKA/PKAs.h>
#include <Misc/sigtypes.h>

using namespace peaks;
using namespace sql;
using namespace std;


// Database connector initialization
DBManager::DBManager(const Cgi_DBConfig &cgi_settings) {
    settings = cgi_settings;
    con = NULL;
    ensure_connection();
}

void DBManager::ensure_connection(){
    bool connected = con != NULL && con->isValid(); //(con->isValid() || con->reconnect());
    if (connected)
        return;
    
    driver = get_driver_instance();
    con = shared_ptr<Connection>(driver->connect(settings.db_host, settings.db_user, settings.db_password));
    con->setSchema(settings.db_database);
    shortid_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT certificate FROM "
                                       "gpg_keyserver WHERE LPAD(CONV(ID,16,10),16,0) LIKE (?);"));

    longid_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT certificate FROM "
                                       "gpg_keyserver WHERE ID = CONV((?),16,10);"));
    fprint_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT certificate FROM "
                                       "gpg_keyserver WHERE fingerprint = unhex(?);"));
    index_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT nLength, pLength, pubAlgorithm, creationTime, "
                                       "kID, name FROM ("
                                       "SELECT length(p.n)*8 as nLength, length(p.p)*8 as pLength, p.pubAlgorithm, "
                                       "hex(p.keyID) as kID, p.creationTime, u.name as name "
                                       "FROM Pubkey AS p INNER JOIN UserID as u ON p.fingerprint = u.fingerprint "
                                       "WHERE MATCH(u.name) AGAINST (? IN BOOLEAN MODE) UNION ALL "
                                       "SELECT 0 as nLength, 0 as pLength, 'NaN' as pubAlgorithm, hex(ownerkeyID) as kID, "
                                       "0 as creationTime, name "
                                       "FROM UserID WHERE MATCH(name) AGAINST (? IN BOOLEAN MODE)) "
                                       "AS keys_list GROUP BY kID"));
    insert_gpg_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("REPLACE INTO gpg_keyserver "
                                       "VALUES (?, ?, ?, ?, ?, 0, 0, ?);"));
    update_gpg_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("UPDATE gpg_keyserver SET "
                                       "certificate = (?), is_unpacked = 0, is_synchronized = 0, hash = (?) WHERE fingerprint = unhex(?) "
                                       "and version = (?);"));
    insert_uid_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("INSERT INTO UserID "
                                       "VALUES (?, ?, ?, 0, 0);"));

    insert_brokenKey_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("INSERT INTO broken_keys (certificate, log) "
                                       "VALUES (?, ?)"));

    vindex_prikey_id_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT hex(keyId) as keyId, creationTime, "
                                       "is_analyzed, length(n)*8 as length_n, length(p)*8 as length_p, pubAlgorithm, version, "
                                       "fingerprint FROM Pubkey WHERE hex(keyId) LIKE (?) and priFingerprint IS NULL "
                                       "UNION "
                                       "SELECT hex(keyId) as keyId, creationTime, is_analyzed, length(n)*8 as length_n, "
                                       "length(p)*8 as length_p, pubAlgorithm, version, fingerprint FROM Pubkey WHERE "
                                       "fingerprint = (SELECT priFingerprint FROM Pubkey WHERE hex(keyId) LIKE (?));"));

    vindex_prikey_fp_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT hex(keyId) as keyId, creationTime, "
                                       "is_analyzed, length(n)*8 as length_n, length(p)*8 as length_p, pubAlgorithm, version, "
                                       "fingerprint FROM Pubkey WHERE fingerprint = UNHEX(?) and priFingerprint IS NULL "
                                       "UNION "
                                       "SELECT hex(keyId) as keyId, creationTime, is_analyzed, length(n)*8 as length_n, "
                                       "length(p)*8 as length_p, pubAlgorithm, version, fingerprint FROM Pubkey WHERE "
                                       "fingerprint = (SELECT priFingerprint FROM Pubkey WHERE fingerprint = UNHEX(?))"));

    vindex_uid_fp_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT fingerprint, name FROM UserID WHERE fingerprint = UNHEX(?)"));

    vindex_signatures_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT hex(issuingKeyId) as issuingKeyId, is_analyzed, "
                                       "type, creationTime, expirationTime, keyExpirationTime, issuingUsername, hex(signedKeyId) as signedKeyId, id, "
                                       "signedUsername, isExpired, isRevocation FROM Signatures WHERE signedFingerprint = UNHEX(?) "
                                       "and (signedUsername = (?) OR signedUsername is NULL) and (sign_Uatt_id = (?) OR "
                                       "sign_Uatt_id is null) ORDER BY creationTime DESC;"));

    vindex_uatt_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT id FROM UserAttribute WHERE fingerprint = UNHEX(?) and name = (?)"));

    vindex_subkey_fp_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT hex(keyId) as keyId, is_analyzed, "
                                       "version, fingerprint, creationTime, length(n)*8 as length_n, length(p)*8 as length_p, "
                                       "pubAlgorithm FROM Pubkey WHERE priFingerprint = UNHEX(?)"));

    vindex_key_vuln_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT vulnerabilityDescription FROM "
                                       "KeyStatus WHERE version = (?) and fingerprint = UNHEX(?) and vulnerabilityCode < 100;"));
    vindex_sign_vuln_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT vulnerabilityDescription FROM "
                                       "SignatureStatus WHERE signature_id = (?) and vulnerabilityCode < 100;"));

    get_by_hash_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT certificate FROM gpg_keyserver WHERE hash = (?);"));
}

// Database class destructor
DBManager::~DBManager() {
}

int DBManager::searchKey(string key, istream*& blob){
    // Strip "0x" from key string
    key.erase(0, 2);
    // Detect input type by lenght
    switch (key.length()) {
        case 8 : // 32-bit key ID
            std::transform(key.begin(), key.end(), key.begin(), ::toupper);
            blob = shortIDQuery(key);
            break;
        case 16 : // 64-bit key ID
            std::transform(key.begin(), key.end(), key.begin(), ::toupper);
            blob = longIDQuery(key);
            break;
        case 32 : // Fingerprint v3 query
            key = key + "00000000"; // Prepend eight 0s
        case 40 : // Fingerprint v4 query
            blob = fingerprintQuery(key);
            break;
        default :
            return ERROR; // Invalid search string lenght
    }
    // Check the result pointer
    return blob ? SUCCESS : KEY_NOT_FOUND;
}

istream* DBManager::shortIDQuery(const string &keyID) {
    ensure_connection();
    // Get the 32 MSBs of the key IDs

    shortid_stmt->setString(1, "%" + keyID);
    result = shared_ptr<ResultSet>(longid_stmt->executeQuery());
    if (result->next()) {
        return result->getBlob("certificate");
    } else {
        return NULL;
    }
}

istream* DBManager::longIDQuery(const string &keyID) {
    ensure_connection();
    // Perform the query on the full key IDs

    longid_stmt->setString(1, keyID);
    result = shared_ptr<ResultSet>(longid_stmt->executeQuery());
    if (result->next()) {
        return result->getBlob("certificate");
    } else {
        return NULL;
    }
}

istream* DBManager::fingerprintQuery(const string &fp) {
    ensure_connection();
    // Query on the fingerprints
    fprint_stmt->setString(1, fp);
    result = shared_ptr<ResultSet>(fprint_stmt->executeQuery());
    if (result->next()) {
        return result->getBlob("certificate");
    } else {
        return NULL;
    }
}

peaks::full_key DBManager::vindexQuery(string id) {
    ensure_connection();
    peaks::full_key res;
    shared_ptr<ResultSet> key_result;
    switch (id.length()) {
        case 8 : // 32-bit key ID
        case 16 : // 64-bit key ID
            vindex_prikey_id_stmt->setString(1, "%" + id);
            vindex_prikey_id_stmt->setString(2, "%" + id);
            key_result = shared_ptr<ResultSet>(vindex_prikey_id_stmt->executeQuery());
            break;
        case 32 : // Fingerprint v3 query
            id = id + "00000000"; // Prepend eight 0s
        case 40 : // Fingerprint v4 query
            vindex_prikey_fp_stmt->setString(1, id);
            vindex_prikey_fp_stmt->setString(2, id);
            key_result = shared_ptr<ResultSet>(vindex_prikey_fp_stmt->executeQuery());
            break;
        default :
            throw std::runtime_error("Invalid search string lenght");
    }
    if (key_result->next()) {
        res.Primary_Key = get_key_info(key_result);
    }
    id = res.Primary_Key.fingerprint;

    // get user
    res.users = get_users(id);

    vindex_subkey_fp_stmt->setString(1, id);
    key_result = shared_ptr<ResultSet>(vindex_subkey_fp_stmt->executeQuery());
    while (key_result->next()) {
        res.subkeys.push_front(get_key_info(key_result));
    }
    return res;
}

forward_list<DB_Key*> *DBManager::indexQuery(string key) {
    ensure_connection();
    forward_list<DB_Key*> *keyList = new forward_list<DB_Key*>();
    //key = OpenPGP::ascii2radix64(key);
    //transform(key.begin(), key.end(), key.begin(), ::toupper);
    
    std::vector<std::string> splitted;
    boost::split(splitted, key, boost::is_any_of(" "), boost::token_compress_on);
    for (auto &str: splitted)
        str.insert(str.begin(), '+');
    string searchString = boost::join(splitted, " ");
    index_stmt->setString(1, searchString);
    index_stmt->setString(2, searchString);
    result = shared_ptr<ResultSet>(index_stmt->executeQuery());
    syslog(LOG_DEBUG, "Found %lu results!", result->rowsCount());
    while (result->next()) {
        int algoNum = result->getInt(3);
        char algoChar = 'c';
        int keyLength = 0;

        string date = string(result->getString(4));
        string keyID = string(result->getString(5));
        string name = string(result->getString(6));
        // If algorith is RSA key bitLength is length(n)*8, otherwise length(p)*8
        switch(algoNum) {
            // RSA Key
            case OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN:
            case OpenPGP::PKA::ID::RSA_SIGN_ONLY:
            case OpenPGP::PKA::ID::RSA_ENCRYPT_ONLY:
                keyLength = result->getInt(1);
                algoChar = 'R';
                break;
            // DSA and ElGamal
            case OpenPGP::PKA::ID::DSA:
            case OpenPGP::PKA::ID::ELGAMAL:
                keyLength = result->getInt(2);
                algoChar = 'D';
                break;
            case OpenPGP::PKA::ID::ECDSA:
            case OpenPGP::PKA::ID::EdDSA:
            case OpenPGP::PKA::ID::ECDH:
                keyLength = result->getInt(2);
                algoChar = 'E';
                break;
            default:
                syslog(LOG_WARNING, "Algorithm not found: %i", algoNum);
                break;
        }
        auto *key = new DB_Key(keyLength, algoChar, keyID, date, name);
        keyList->push_front(key);
    }
    return keyList;
}

void DBManager::insert_gpg_keyserver(const gpg_keyserver_data &gk) {
    ensure_connection();
    try {
        insert_gpg_stmt->setInt(1, gk.version);
        insert_gpg_stmt->setBigInt(2, gk.ID);
        insert_gpg_stmt->setBlob(3, new istringstream(gk.fingerprint));
        insert_gpg_stmt->setBlob(4, new istringstream(gk.certificate));
        insert_gpg_stmt->setString(5, gk.hash);
        insert_gpg_stmt->setInt(6, gk.error_code);
        insert_gpg_stmt->executeQuery();
    }catch (SQLException &e){
        if(e.getErrorCode() == 1062){
            syslog(LOG_INFO, "insert_gpg_stmt FAILED - key already in the database (but this error must not happen) - %s", e.what());
        }else {
            syslog(LOG_ERR, "insert_gpg_stmt FAILED - %s", e.what());
        }
    }
}

void DBManager::update_gpg_keyserver(const gpg_keyserver_data &gk) {
    ensure_connection();
    try {
        update_gpg_stmt->setBlob(1, new istringstream(gk.certificate));
        update_gpg_stmt->setString(2, gk.hash);
        update_gpg_stmt->setString(3, hexlify(gk.fingerprint, true));
        update_gpg_stmt->setInt(4, gk.version);
        update_gpg_stmt->executeQuery();
    }catch (SQLException &e){
        syslog(LOG_ERR, "update_gpg_stmt FAILED - %s", e.what());
    }
}

void DBManager::insert_user_id(const userID_data &uid) {
    ensure_connection();
    try {
        insert_uid_stmt->setBigInt(1, uid.ownerkeyID);
        insert_uid_stmt->setString(2, uid.fingerprint);
        insert_uid_stmt->setString(3, uid.name);
        insert_uid_stmt->setString(4, uid.email);
        insert_uid_stmt->executeQuery();
    }catch(SQLException &e){
        if(e.getErrorCode() == 1062){
            syslog(LOG_INFO, "insert_uid_stmt FAILED - user already in the database - %s", e.what());
        }else{
            syslog(LOG_ERR, "insert_uid_stmt FAILED - %s", e.what());
        }
    }
}

void DBManager::insert_broken_key(const string &cert, const string &comment) {
    ensure_connection();
    try {
        insert_brokenKey_stmt->setBlob(1, new istringstream(cert));
        insert_brokenKey_stmt->setString(2, comment);
        insert_brokenKey_stmt->executeQuery();
    }catch (SQLException &e){
        syslog(LOG_ERR, "insert_brokenKey_stmt FAILED - %s", e.what());
    }
}

key DBManager::get_key_info(const std::shared_ptr<sql::ResultSet> &key_result) {
    peaks::key tmp_key;

    tmp_key.fingerprint = hexlify(key_result->getString("fingerprint"), true);
    tmp_key.keyID = string(key_result->getString("keyId"));
    // If algorith is RSA key bitLength is length(n)*8, otherwise length(p)*8
    switch(key_result->getInt("pubAlgorithm")) {
        // RSA Key
        case OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN:
        case OpenPGP::PKA::ID::RSA_SIGN_ONLY:
        case OpenPGP::PKA::ID::RSA_ENCRYPT_ONLY:
            tmp_key.bits = to_string(key_result->getInt("length_n"));
            tmp_key.algoChar = 'R';
            break;
            // DSA and ElGamal
        case OpenPGP::PKA::ID::DSA:
        case OpenPGP::PKA::ID::ELGAMAL:
        case OpenPGP::PKA::ID::RESERVED_ELGAMAL:
        case OpenPGP::PKA::ID::RESERVED_DH:
            tmp_key.bits = to_string(key_result->getInt("length_p"));
            tmp_key.algoChar = 'D';
            break;
        case OpenPGP::PKA::ID::ECDSA:
        case OpenPGP::PKA::ID::EdDSA:
        case OpenPGP::PKA::ID::ECDH:
            tmp_key.bits = to_string(key_result->getInt("length_p"));
            tmp_key.algoChar = 'E';
            break;
        default:
            tmp_key.bits = "0";
            tmp_key.algoChar = 'N';
            syslog(LOG_WARNING, "Algorithm not found: %i", result->getInt("pubAlgorithm"));
            break;
    }
    tmp_key.creation_time = key_result->getString("creationTime").substr(0, 10);
    tmp_key.signatures = get_signatures(hexlify(key_result->getString("fingerprint"), true));
    if (key_result->getUInt("is_analyzed") == 1){
        tmp_key.vulnerabilities = get_key_vuln(key_result->getUInt("version"), hexlify(key_result->getString("fingerprint"), true));
    }
    return tmp_key;
}

std::forward_list<signature> DBManager::get_signatures(const std::string &signedFingerprint, const std::string &signedUsername, const int &ua_id) {
    ensure_connection();
    std::forward_list<signature> signatures;
    vindex_signatures_stmt->setString(1, signedFingerprint);
    vindex_signatures_stmt->setString(2, signedUsername);
    vindex_signatures_stmt->setInt(3, ua_id);
    shared_ptr<ResultSet> sign_result = shared_ptr<ResultSet>(vindex_signatures_stmt->executeQuery());
    while(sign_result->next()){
        peaks::signature tmp_sign;
        tmp_sign.hex_type = sign_result->getUInt("type");
        if (sign_result->getBoolean("isExpired")){
            tmp_sign.type = "exp";
        }else{
            switch (tmp_sign.hex_type){
                case OpenPGP::Signature_Type::GENERIC_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
                    tmp_sign.type = "sig";
                    break;
                case OpenPGP::Signature_Type::PERSONA_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
                    tmp_sign.type = "sig1";
                    break;
                case OpenPGP::Signature_Type::CASUAL_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
                    tmp_sign.type = "sig2";
                    break;
                case OpenPGP::Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
                    tmp_sign.type = "sig3";
                    break;
                case OpenPGP::Signature_Type::SUBKEY_BINDING_SIGNATURE:
                    tmp_sign.type = "sbind";
                    break;
                case OpenPGP::Signature_Type::KEY_REVOCATION_SIGNATURE:
                case OpenPGP::Signature_Type::SUBKEY_REVOCATION_SIGNATURE:
                case OpenPGP::Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE:
                    tmp_sign.type = "revok";
                    break;
                case OpenPGP::Signature_Type::SIGNATURE_DIRECTLY_ON_A_KEY:
                    tmp_sign.type = "dirct";
                    break;
                default:
                    tmp_sign.type = "sig";
                    break;
            }
        }
        tmp_sign.issuingKeyID = sign_result->getString("issuingKeyId");
        tmp_sign.signedKeyID = sign_result->getString("signedKeyId");
        tmp_sign.signedUsername = sign_result->getString("signedUsername");
        tmp_sign.creation_time = sign_result->getString("creationTime").substr(0, 10);
        tmp_sign.exp_time = sign_result->getString("expirationTime").substr(0, 10);
        tmp_sign.key_exp_time = sign_result->getString("keyExpirationTime").substr(0, 10);
        if (sign_result->getString("issuingKeyId") == sign_result->getString("signedKeyId")){
            tmp_sign.issuingUID = "[selfsig]";
        }else if (sign_result->getString("issuingUsername") == "" ||
                tmp_sign.hex_type == OpenPGP::Signature_Type::SUBKEY_BINDING_SIGNATURE){
            tmp_sign.issuingUID = "[]";
        }else{
            tmp_sign.issuingUID = sign_result->getString("issuingUsername");
        }
        tmp_sign.is_revocation = sign_result->getBoolean("isRevocation");

        if (tmp_sign.creation_time.empty()){
            tmp_sign.creation_time = "__________";
        }

        if (tmp_sign.exp_time.empty()){
            tmp_sign.exp_time = "__________";
        }

        if (tmp_sign.key_exp_time.empty()){
            tmp_sign.key_exp_time = "__________";
        }
        if (sign_result->getUInt("is_analyzed") == 1){
            tmp_sign.vulnerabilities = get_sign_vuln(sign_result->getUInt("id"));
        }

        signatures.push_front(tmp_sign);
    }
    for (const auto &s_1: signatures){
        if (!s_1.is_revocation){
            for (const auto &s_2: signatures){
                if (s_2.is_revocation && s_1.is_its_revocation(s_2)){
                    signatures.remove(s_1);
                }
            }
        }
    }
    return signatures;
}

std::forward_list<ua> DBManager::get_userAtt(const uid &tmp_uid) {
    ensure_connection();
    forward_list<ua> ua_list;
    vindex_uatt_stmt->setString(1, tmp_uid.fingerprint);
    vindex_uatt_stmt->setString(2, tmp_uid.name);
    shared_ptr<ResultSet> ua_result = shared_ptr<ResultSet>(vindex_uatt_stmt->executeQuery());
    while(ua_result ->next()){
        peaks::ua tmp_ua;
        tmp_ua.signatures = get_signatures(tmp_uid.fingerprint, "", ua_result->getInt("id"));
        ua_list.push_front(tmp_ua);
    }
    return ua_list;
}

std::forward_list<uid> DBManager::get_users(const std::string &id) {
    ensure_connection();
    forward_list<uid> uid_list;
    vindex_uid_fp_stmt->setString(1, id);
    shared_ptr<ResultSet> uid_result = shared_ptr<ResultSet>(vindex_uid_fp_stmt->executeQuery());
    while (uid_result->next()) {
        peaks::uid tmp_uid;
        tmp_uid.name = uid_result->getString("name");
        tmp_uid.fingerprint = hexlify(uid_result->getString("fingerprint"), true);
        tmp_uid.signatures = get_signatures(tmp_uid.fingerprint, tmp_uid.name);
        tmp_uid.user_attributes = get_userAtt(tmp_uid);
        uid_list.push_front(tmp_uid);
    }
    return uid_list;
}

std::forward_list<std::string> DBManager::get_key_vuln(const unsigned int &version, const std::string &fingerprint) {
    ensure_connection();
    forward_list<string> vulns;
    vindex_key_vuln_stmt->setInt(1, version);
    vindex_key_vuln_stmt->setString(2, fingerprint);
    shared_ptr<ResultSet> vuln_result = shared_ptr<ResultSet>(vindex_key_vuln_stmt->executeQuery());
    while (vuln_result->next()) {
        vulns.push_front(vuln_result->getString("vulnerabilityDescription"));
    }
    return vulns;
}

std::forward_list<std::string> DBManager::get_sign_vuln(const unsigned int &sign_id) {
    ensure_connection();
    forward_list<string> vulns;
    vindex_sign_vuln_stmt->setInt(1, sign_id);
    shared_ptr<ResultSet> vuln_result = shared_ptr<ResultSet>(vindex_sign_vuln_stmt->executeQuery());
    while (vuln_result->next()) {
        vulns.push_front(vuln_result->getString("vulnerabilityDescription"));
    }
    return vulns;
}

string DBManager::get_key_by_hash(const string &hash) {
    ensure_connection();
    string out = "";
    try{
        get_by_hash_stmt->setString(1, hash);
        result = shared_ptr<ResultSet>(get_by_hash_stmt->executeQuery());
        while (result->next()){
            out += result->getString("certificate");
        }
    }catch (exception &e){
        syslog(LOG_WARNING, "Hash not found: requested not existing hashing during recon: %s", hash.c_str());
    }
    return out;
}
