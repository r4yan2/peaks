#include <cstdlib>
#include <cstring>
#include <iostream>
#include <syslog.h>

// Local files includes
#include "db.h"

#include <common/includes.h>
#include <boost/algorithm/string.hpp>

using namespace std;

namespace peaks{
namespace pks{

// Database connector initialization
CGI_DBManager::CGI_DBManager(): DBManager() {
    check_sql_mode();
    connect_schema();
    prepare_queries();
}

void CGI_DBManager::prepare_queries(){
    shortid_stmt = prepare_query("SELECT filename, origin, len FROM "
                                       "gpg_keyserver WHERE LPAD(CONV(ID,16,10),16,0) LIKE (?);");

    longid_stmt = prepare_query("SELECT filename, origin, len FROM "
                                       "gpg_keyserver WHERE ID = CONV((?),16,10);");
    fprint_stmt = prepare_query("SELECT filename, origin, len FROM "
                                       "gpg_keyserver WHERE fingerprint = unhex(?);");
    index_stmt = prepare_query("SELECT nLength, pLength, pubAlgorithm, creationTime, "
                                       "kID, name FROM ("
                                       "SELECT length(p.n)*8 as nLength, length(p.p)*8 as pLength, p.pubAlgorithm, "
                                       "hex(p.keyID) as kID, p.creationTime, u.name as name "
                                       "FROM Pubkey AS p INNER JOIN UserID as u ON p.fingerprint = u.fingerprint "
                                       "WHERE MATCH(u.name) AGAINST (? IN BOOLEAN MODE) UNION ALL "
                                       "SELECT 0 as nLength, 0 as pLength, 'NaN' as pubAlgorithm, hex(ownerkeyID) as kID, "
                                       "0 as creationTime, name "
                                       "FROM UserID WHERE MATCH(name) AGAINST (? IN BOOLEAN MODE)) "
                                       "AS keys_list GROUP BY kID");

    insert_uid_stmt = prepare_query("INSERT INTO UserID "
                                       "VALUES (?, ?, ?, 0, 0);");

    vindex_prikey_full_id_stmt = prepare_query("SELECT hex(keyId) as keyId, creationTime, "
                                       "is_analyzed, length(n)*8 as length_n, length(p)*8 as length_p, pubAlgorithm, version, "
                                       "fingerprint FROM Pubkey WHERE keyId = CAST(CONV((?),16,10) AS UNSIGNED INTEGER) and priFingerprint IS NULL "
                                       "UNION "
                                       "SELECT hex(keyId) as keyId, creationTime, is_analyzed, length(n)*8 as length_n, "
                                       "length(p)*8 as length_p, pubAlgorithm, version, fingerprint FROM Pubkey WHERE "
                                       "fingerprint = (SELECT priFingerprint FROM Pubkey WHERE keyId = CAST(CONV((?),16,10) AS UNSIGNED INTEGER));");

    vindex_prikey_short_id_stmt = prepare_query("SELECT hex(keyId) as keyId, creationTime, "
                                       "is_analyzed, length(n)*8 as length_n, length(p)*8 as length_p, pubAlgorithm, version, "
                                       "fingerprint FROM Pubkey WHERE hex(keyId) LIKE (?) and priFingerprint IS NULL "
                                       "UNION "
                                       "SELECT hex(keyId) as keyId, creationTime, is_analyzed, length(n)*8 as length_n, "
                                       "length(p)*8 as length_p, pubAlgorithm, version, fingerprint FROM Pubkey WHERE "
                                       "fingerprint = (SELECT priFingerprint FROM Pubkey WHERE hex(keyId) LIKE (?));");

    vindex_prikey_fp_stmt = prepare_query("SELECT hex(keyId) as keyId, creationTime, "
                                       "is_analyzed, length(n)*8 as length_n, length(p)*8 as length_p, pubAlgorithm, version, "
                                       "fingerprint FROM Pubkey WHERE fingerprint = UNHEX(?) and priFingerprint IS NULL "
                                       "UNION "
                                       "SELECT hex(keyId) as keyId, creationTime, is_analyzed, length(n)*8 as length_n, "
                                       "length(p)*8 as length_p, pubAlgorithm, version, fingerprint FROM Pubkey WHERE "
                                       "fingerprint = (SELECT priFingerprint FROM Pubkey WHERE fingerprint = UNHEX(?))");

    vindex_uid_fp_stmt = prepare_query("SELECT fingerprint, name FROM UserID WHERE fingerprint = UNHEX(?)");

    vindex_signatures_stmt = prepare_query("SELECT hex(issuingKeyId) as issuingKeyId, is_analyzed, "
                                       "type, creationTime, expirationTime, keyExpirationTime, issuingUsername, hex(signedKeyId) as signedKeyId, id, "
                                       "signedUsername, isExpired, isRevocation FROM Signatures WHERE signedFingerprint = UNHEX(?) "
                                       "and (signedUsername = (?) OR signedUsername is NULL) and (sign_Uatt_id = (?) OR "
                                       "sign_Uatt_id is null) ORDER BY creationTime DESC;");
    get_signature_issuingusername_stmt = prepare_query("select COALESCE(S.issuingUsername, U.name) as issuingUsername from (select * FROM Signatures WHERE issuingKeyID = UNHEX(?) AND signedKeyID = UNHEX(?) AND signedUsername = ? AND signedFingerprint = ?) as S JOIN UserID U on S.issuingKeyId=U.ownerKeyId;");

    vindex_uatt_stmt = prepare_query("SELECT id FROM UserAttribute WHERE fingerprint = UNHEX(?) and name = (?)");

    vindex_subkey_fp_stmt = prepare_query("SELECT hex(keyId) as keyId, is_analyzed, "
                                       "version, fingerprint, creationTime, length(n)*8 as length_n, length(p)*8 as length_p, "
                                       "pubAlgorithm FROM Pubkey WHERE priFingerprint = UNHEX(?)");

    vindex_key_vuln_stmt = prepare_query("SELECT vulnerabilityDescription FROM "
                                       "KeyStatus WHERE version = (?) and fingerprint = UNHEX(?) and vulnerabilityCode < 100;");
    vindex_sign_vuln_stmt = prepare_query("SELECT vulnerabilityDescription FROM "
                                       "SignatureStatus WHERE signature_id = (?) and vulnerabilityCode < 100;");

    get_pnodes_stmt = prepare_query("SELECT node_key, key_size, num_elements, leaf FROM ptree");
    
    get_certificates_unpacking_status_stmt = prepare_query("select is_unpacked, count(is_unpacked) as aggr from gpg_keyserver group by is_unpacked;");

    get_certificates_with_attributes_stmt = prepare_query("SELECT DISTINCT(gpg_keyserver.id) as unique_id FROM gpg_keyserver join UserAttribute on gpg_keyserver.fingerprint=UserAttribute.fingerprint");

    get_certificates_analysis_stmt = prepare_query("SELECT len as length, (ua.id IS NOT NULL) as hasUserAttribute, YEAR(pu.creationtime) as year, is_unpacked FROM gpg_keyserver as gp LEFT JOIN UserAttribute as ua on gp.fingerprint = ua.fingerprint LEFT JOIN Pubkey as pu on pu.keyId = gp.id");
    get_certificates_generic_stats_stmt = prepare_query("SELECT max(len) as maxlen, min(len) as minlen, count(len) as countlen from gpg_keyserver");
    get_user_attributes_data_stmt = prepare_query("SELECT LENGTH(image) as length, (encoding IS NOT NULL) as isImage FROM UserAttribute");
    get_pubkey_data_stmt = prepare_query("SELECT pubAlgorithm, YEAR(creationtime) as year, BIT_LENGTH(n) as n_length, BIT_LENGTH(p) as p_length, BIT_LENGTH(q) as q_length, vulnerabilityDescription, vulnerabilityCode, is_analyzed FROM Pubkey LEFT JOIN KeyStatus on Pubkey.fingerprint = KeyStatus.fingerprint WHERE YEAR(creationtime) >= (?) and YEAR(creationtime) <= (?)");
    get_signature_data_stmt = prepare_query("SELECT isRevocation, isExpired, pubAlgorithm, YEAR(creationTime) as year, issuingKeyId, signedKeyId from Signatures");
    get_userid_data_stmt = prepare_query("SELECT ownerkeyid, name FROM UserID");
}

// Database class destructor
CGI_DBManager::~CGI_DBManager() {
}

int CGI_DBManager::searchKey(string key, std::string & blob){
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
    return blob != "" ? SUCCESS : KEY_NOT_FOUND;
}

std::string CGI_DBManager::shortIDQuery(const string &keyID) {

    check_database_connection();
    // Get the 32 MSBs of the key IDs

    shortid_stmt->setString(1, "%" + keyID);
    std::unique_ptr<DBResult> result = shortid_stmt->execute();
    if (result->next()) {
        std::string filename = result->getString("filename");
        int origin = result->getInt("origin");
        int len = result->getInt("len");
        return get_certificate_from_filestore(filename, origin, len);
    } else {
        return "";
    }
}

std::string CGI_DBManager::longIDQuery(const string &keyID) {
    check_database_connection();
    // Perform the query on the full key IDs

    longid_stmt->setString(1, keyID);
    std::unique_ptr<DBResult> result = longid_stmt->execute();
    if (result->next()) {
        std::string filename = result->getString("filename");
        int origin = result->getInt("origin");
        int len = result->getInt("len");
        return get_certificate_from_filestore(filename, origin, len);
    } else {
        return "";
    }
}

std::string CGI_DBManager::fingerprintQuery(const string &fp) {
    check_database_connection();
    // Query on the fingerprints
    fprint_stmt->setString(1, fp);
    std::unique_ptr<DBResult> result = fprint_stmt->execute();
    if (result->next()) {
        std::string filename = result->getString("filename");
        int origin = result->getInt("origin");
        int len = result->getInt("len");
        return get_certificate_from_filestore(filename, origin, len);
    } else {
        return "";
    }
}

full_key CGI_DBManager::vindexQuery(string id) {
    check_database_connection();
    full_key res;
    std::unique_ptr<DBResult> key_result;
    switch (id.length()) {
        case 8 : // 32-bit key ID
            vindex_prikey_short_id_stmt->setString(1, "%" + id);
            vindex_prikey_short_id_stmt->setString(2, "%" + id);
            key_result = vindex_prikey_short_id_stmt->execute();
            break;
        case 16 : // 64-bit key ID
            vindex_prikey_full_id_stmt->setString(1, id);
            vindex_prikey_full_id_stmt->setString(2, id);
            key_result = vindex_prikey_full_id_stmt->execute();
            break;
        case 32 : // Fingerprint v3 query
            id = id + "00000000"; // Prepend eight 0s
        case 40 : // Fingerprint v4 query
            vindex_prikey_fp_stmt->setString(1, id);
            vindex_prikey_fp_stmt->setString(2, id);
            key_result = vindex_prikey_fp_stmt->execute();
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
    key_result = vindex_subkey_fp_stmt->execute();
    while (key_result->next()) {
        res.subkeys.push_front(get_key_info(key_result));
    }
    return res;
}

forward_list<DB_Key*> *CGI_DBManager::indexQuery(string key) {
    check_database_connection();
    forward_list<DB_Key*> *keyList = new forward_list<DB_Key*>();
    //key = OpenPGP::ascii2radix64(key);
    //transform(key.begin(), key.end(), key.begin(), ::toupper);
    
    //std::vector<std::string> splitted;
    //boost::split(splitted, key, boost::is_any_of(" ()*+-<>@~"), boost::token_compress_on);
    //for (auto &str: splitted)
    //    str.insert(str.begin(), '+');
    //string searchString = boost::join(splitted, " ");
    auto searchString = key;
    index_stmt->setString(1, searchString);
    index_stmt->setString(2, searchString);
    std::unique_ptr<DBResult> result = index_stmt->execute();
    syslog(LOG_DEBUG, "Found %lu results!", result->size());
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

void CGI_DBManager::insert_user_id(const userID &uid) {
    check_database_connection();
    try {
        insert_uid_stmt->setBigInt(1, uid.ownerkeyID);
        insert_uid_stmt->setString(2, uid.fingerprint);
        insert_uid_stmt->setString(3, uid.name);
        insert_uid_stmt->execute();
    }catch(std::exception &e){
        syslog(LOG_ERR, "insert_uid_stmt FAILED - %s", e.what());
    }
}

void CGI_DBManager::insert_broken_key(const string &cert, const string &comment) {
    check_database_connection();
    try {
        insert_brokenKey_stmt->setBlob(1, new istringstream(cert));
        insert_brokenKey_stmt->setString(2, comment);
        insert_brokenKey_stmt->execute();
    }catch (std::exception &e){
        syslog(LOG_ERR, "insert_brokenKey_stmt FAILED - %s", e.what());
    }
}

key CGI_DBManager::get_key_info(const std::unique_ptr<DBResult> & key_result) {
    key tmp_key;

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
        //case OpenPGP::PKA::ID::RESERVED_ELGAMAL:
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
            syslog(LOG_WARNING, "Algorithm not found: %i", key_result->getInt("pubAlgorithm"));
            break;
    }
    tmp_key.creation_time = key_result->getString("creationTime").substr(0, 10);
    tmp_key.signatures = get_signatures(hexlify(key_result->getString("fingerprint"), true));
    if (key_result->getInt("is_analyzed") == 1){
        tmp_key.vulnerabilities = get_key_vuln(key_result->getInt("version"), hexlify(key_result->getString("fingerprint"), true));
    }
    return tmp_key;
}

std::forward_list<signature> CGI_DBManager::get_signatures(const std::string &signedFingerprint, const std::string &signedUsername, const int &ua_id) {
    check_database_connection();
    std::forward_list<signature> signatures;
    vindex_signatures_stmt->setString(1, signedFingerprint);
    vindex_signatures_stmt->setString(2, signedUsername);
    vindex_signatures_stmt->setInt(3, ua_id);
    std::unique_ptr<DBResult> sign_result = vindex_signatures_stmt->execute();
    while(sign_result->next()){
        signature tmp_sign;
        tmp_sign.hex_type = sign_result->getInt("type");
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
        }else{
            //query issuingUsername
            get_signature_issuingusername_stmt->setString(1, tmp_sign.issuingKeyID);
            get_signature_issuingusername_stmt->setString(2, tmp_sign.signedKeyID);
            get_signature_issuingusername_stmt->setString(3, signedUsername);
            get_signature_issuingusername_stmt->setString(4, signedFingerprint);
            std::unique_ptr<DBResult> issuingusername_result = get_signature_issuingusername_stmt->execute();
            std::string issuingUsername = issuingusername_result->next() ? issuingusername_result->getString("issuingUsername") : "";
            if (issuingUsername == "" || tmp_sign.hex_type == OpenPGP::Signature_Type::SUBKEY_BINDING_SIGNATURE){
                tmp_sign.issuingUID = "[]";
            }else{
                tmp_sign.issuingUID = issuingUsername;
            }
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
        if (sign_result->getInt("is_analyzed") == 1){
            tmp_sign.vulnerabilities = get_sign_vuln(sign_result->getInt("id"));
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

std::forward_list<ua> CGI_DBManager::get_userAtt(const uid &tmp_uid) {
    check_database_connection();
    forward_list<ua> ua_list;
    vindex_uatt_stmt->setString(1, tmp_uid.fingerprint);
    vindex_uatt_stmt->setString(2, tmp_uid.name);
    std::unique_ptr<DBResult> ua_result = vindex_uatt_stmt->execute();
    while(ua_result ->next()){
        ua tmp_ua;
        tmp_ua.signatures = get_signatures(tmp_uid.fingerprint, "", ua_result->getInt("id"));
        ua_list.push_front(tmp_ua);
    }
    return ua_list;
}

std::forward_list<uid> CGI_DBManager::get_users(const std::string &id) {
    check_database_connection();
    forward_list<uid> uid_list;
    vindex_uid_fp_stmt->setString(1, id);
    std::unique_ptr<DBResult> uid_result = vindex_uid_fp_stmt->execute();
    while (uid_result->next()) {
        uid tmp_uid;
        tmp_uid.name = uid_result->getString("name");
        tmp_uid.fingerprint = hexlify(uid_result->getString("fingerprint"), true);
        tmp_uid.signatures = get_signatures(tmp_uid.fingerprint, tmp_uid.name);
        tmp_uid.user_attributes = get_userAtt(tmp_uid);
        uid_list.push_front(tmp_uid);
    }
    return uid_list;
}

std::forward_list<std::string> CGI_DBManager::get_key_vuln(const unsigned int &version, const std::string &fingerprint) {
    check_database_connection();
    forward_list<string> vulns;
    vindex_key_vuln_stmt->setInt(1, version);
    vindex_key_vuln_stmt->setString(2, fingerprint);
    std::unique_ptr<DBResult> vuln_result = vindex_key_vuln_stmt->execute();
    while (vuln_result->next()) {
        vulns.push_front(vuln_result->getString("vulnerabilityDescription"));
    }
    return vulns;
}

std::forward_list<std::string> CGI_DBManager::get_sign_vuln(const unsigned int &sign_id) {
    check_database_connection();
    forward_list<string> vulns;
    vindex_sign_vuln_stmt->setInt(1, sign_id);
    std::unique_ptr<DBResult> vuln_result = vindex_sign_vuln_stmt->execute();
    while (vuln_result->next()) {
        vulns.push_front(vuln_result->getString("vulnerabilityDescription"));
    }
    return vulns;
}

string CGI_DBManager::get_key_by_hash(const string &hash) {
    check_database_connection();
    return get_certificate_from_filestore(hash);
}

vector<DBStruct::node> CGI_DBManager::get_pnodes(){
    vector<DBStruct::node> res;
    try{
        std::unique_ptr<DBResult> result = get_pnodes_stmt->execute();
        while (result->next()){
            DBStruct::node node;
            node.key = result->getString("node_key");
            node.key_size = result->getInt("key_size");
            node.num_elements = result->getInt("num_elements");
            node.leaf = result->getBoolean("leaf");
            res.push_back(node);
        }
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch nodes from the DB: %s", e.what());
    }
    return res;
}

std::tuple<int, int, int> CGI_DBManager::get_certificates_generic_stats(){
    std::tuple<int, int, int> res = {0,0,0};
    try{
        std::unique_ptr<DBResult> result = get_certificates_generic_stats_stmt->execute();
        if(result->next()){
            res = {
                result->getInt("maxlen"),
                result->getInt("minlen"),
                result->getInt("countlen")
            };
        }
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    return res;
}

std::vector<std::tuple<int, int>> CGI_DBManager::get_certificates_unpacking_status(){
    std::vector<std::tuple<int, int>> res;
    try{
        std::unique_ptr<DBResult> result = get_certificates_unpacking_status_stmt->execute();
        if(result->next()){
            res.push_back({
                result->getInt("is_unpacked"),
                result->getInt("aggr"),
            });
        }
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    return res;
}


certificate_data_t CGI_DBManager::get_certificate_data_from_iterator(std::shared_ptr<DBResult> &result){
    certificate_data_t out;
    if(result->next()){
        return certificate_data_t(
            result->getInt("length"),
            result->getBoolean("hasUserAttribute"),
            result->getInt("year"),
            result->getInt("is_unpacked")
        );
    }
    return out;
}

std::shared_ptr<DBResult> CGI_DBManager::get_certificates_analysis_iterator(){
    std::shared_ptr<DBResult> res;
    try{
        res = get_certificates_analysis_stmt->execute();
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    return res;
}

userattribute_data_t CGI_DBManager::get_user_attribute_data_from_iterator(std::shared_ptr<DBResult> &result){
   if(result->next()){
       return userattribute_data_t(
           result->getInt("length"),
           result->getBoolean("isImage")
       );
   }
   return userattribute_data_t();
}

std::shared_ptr<DBResult> CGI_DBManager::get_user_attributes_data_iterator(){
    std::shared_ptr<DBResult> result;
    try{
        result = get_user_attributes_data_stmt->execute();
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    return result;

}


pubkey_data_t CGI_DBManager::get_pubkey_data_from_iterator(std::shared_ptr<DBResult> &result){
     if(result->next()){
        return pubkey_data_t(
            result->getInt("pubAlgorithm"),
            result->getInt("year"),
            result->getInt("n_length"),
            result->getInt("p_length"),
            result->getInt("q_length"),
            result->getString("vulnerabilityDescription"),
            result->getInt("vulnerabilityCode"),
            result->getInt("is_analyzed")
        );
     }
    return pubkey_data_t();
}

std::shared_ptr<DBResult> CGI_DBManager::get_pubkey_data_iterator(const int &min_year, const int &max_year){
    std::shared_ptr<DBResult> res;
    try{
        get_pubkey_data_stmt->setInt(1, min_year);
        get_pubkey_data_stmt->setInt(2, max_year);
        res = get_pubkey_data_stmt->execute();
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    return res;

}

signature_data_t CGI_DBManager::get_signature_data_from_iterator(std::shared_ptr<DBResult> &result){
    if(result->next()){
        return signature_data_t(
            result->getInt("isRevocation"),
            result->getInt("isExpired"),
            result->getInt("pubAlgorithm"),
            result->getInt("year"),
            result->getInt("issuingKeyId"),
            result->getInt("signedKeyId")
        );
    }
    return signature_data_t();
}

std::shared_ptr<DBResult> CGI_DBManager::get_signature_data_iterator(){
    std::shared_ptr<DBResult> result;
    try{
        result = get_signature_data_stmt->execute();
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    return result;

}


userid_data_t CGI_DBManager::get_userid_data_from_iterator(std::shared_ptr<DBResult> &result){
    if(result->next()){
        return userid_data_t(
            result->getInt("ownerkeyid"),
            result->getString("name")
        );
    }
    return userid_data_t();
}

std::shared_ptr<DBResult> CGI_DBManager::get_userid_data_iterator(){
    std::shared_ptr<DBResult> result;
    try{
        result = get_userid_data_stmt->execute();
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    return result;

}
}
}
