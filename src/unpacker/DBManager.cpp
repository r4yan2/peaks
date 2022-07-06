#include <sys/syslog.h>
#include <cstring>
#include <thread>

#include "DBManager.h"
#include <common/config.h>
#include <common/FileManager.h>

using namespace peaks::common;
using namespace std;

namespace peaks{
namespace unpacker{

UNPACKER_DBManager::UNPACKER_DBManager():DBManager(){
    tables = {
        Utils::TABLES::PUBKEY,
        Utils::TABLES::SIGNATURE,
        Utils::TABLES::SELF_SIGNATURE, 
        Utils::TABLES::USER_ATTRIBUTES,
        Utils::TABLES::UNPACKER_ERRORS,
        Utils::TABLES::USERID,
        Utils::TABLES::UNPACKED,
    };
    connect_schema();
    prepare_queries();
}

void UNPACKER_DBManager::prepare_queries(){
    //con->createStatement()->execute("set sql_log_bin = 0;");
    //con->createStatement()->execute("set foreign_key_checks = 0;");

    // Create prepared Statements
    get_analyzable_cert_stmt = prepare_query("SELECT version, fingerprint, filename, origin, len, hash "
                                         "FROM gpg_keyserver WHERE is_unpacked = 0 LIMIT ?");
    
    get_signature_by_index = prepare_query("SELECT id "
                                         "FROM Signatures WHERE r = (?) and s = (?)");
    
    set_unpacking_status_stmt = prepare_query("UPDATE gpg_keyserver SET is_unpacked = 3 WHERE version = (?) and fingerprint = (?)");
    
    update_issuing_fingerprint = prepare_query("UPDATE Signatures INNER JOIN Pubkey on issuingKeyId = KeyId SET issuingFingerprint = fingerprint where isnull(issuingFingerprint) and issuingKeyId = KeyId;");
    update_issuing_username = prepare_query("UPDATE Signatures INNER JOIN UserID on issuingFingerprint = fingerprint SET issuingUsername = name where isnull(issuingUsername) and issuingFingerprint = fingerprint;");
    update_expired = prepare_query("UPDATE Signatures SET isExpired = 1 WHERE expirationTime < NOW();");
    update_valid = prepare_query("UPDATE Signatures as s1 SET s1.isValid = -1 WHERE s1.isExpired = 1 or isRevoked = 1;");
    update_revoked_1 = prepare_query("INSERT IGNORE INTO revocationSignatures select issuingKeyId, "
                  "signedFingerprint, signedUsername FROM Signatures WHERE isRevocation = 1;");
    update_revoked_2 = prepare_query("UPDATE Signatures INNER JOIN revocationSignatures on (Signatures.issuingKeyId = revocationSignatures.issuingKeyId and Signatures.signedFingerprint = revocationSignatures.signedFingerprint and Signatures.signedUsername = revocationSignatures.signedUsername) set isRevoked = 1, isValid = -1 where isRevoked = 0 and isRevocation = 0;");
}

UNPACKER_DBManager::~UNPACKER_DBManager(){
};

vector<DBStruct::gpg_keyserver_data> UNPACKER_DBManager::get_certificates(const unsigned long &l) {
    vector<DBStruct::gpg_keyserver_data> certificates;
    get_analyzable_cert_stmt->setString(1, to_string(l));
    std::unique_ptr<DBResult> result = get_analyzable_cert_stmt->execute();
    while(result->next()){
        DBStruct::gpg_keyserver_data tmp_field;
        tmp_field.version = result->getInt("version");
        tmp_field.fingerprint = result->getString("fingerprint");
        tmp_field.filename = result->getString("filename");
        tmp_field.origin = result->getInt("origin");
        tmp_field.len = result->getInt("len");
        tmp_field.certificate = get_certificate_from_filestore(tmp_field.filename, tmp_field.origin, tmp_field.len);
        certificates.push_back(tmp_field);
    }
    return certificates;
}

std::shared_ptr<DBResult> UNPACKER_DBManager::get_certificates_iterator(const unsigned long &l) {
    vector<DBStruct::gpg_keyserver_data> certificates;
    get_analyzable_cert_stmt->setString(1, to_string(l));
    std::shared_ptr<DBResult> result = get_analyzable_cert_stmt->execute();
    return result;
}

DBStruct::gpg_keyserver_data UNPACKER_DBManager::get_certificate_from_results(const std::shared_ptr<DBResult> & result){
    std::lock_guard<std::mutex> lock(mtx);
    DBStruct::gpg_keyserver_data tmp_field;
    if(result->next()){
        tmp_field.version = result->getInt("version");
        tmp_field.fingerprint = result->getString("fingerprint");
        tmp_field.filename = result->getString("filename");
        tmp_field.origin = result->getInt("origin");
        tmp_field.len = result->getInt("len");
        tmp_field.hash = result->getString("hash");
        tmp_field.certificate = get_certificate_from_filestore(tmp_field.filename, tmp_field.origin, tmp_field.len);
    }
    return tmp_field;
}

bool UNPACKER_DBManager::existSignature(const DBStruct::signatures &s){
    try {
        get_signature_by_index->setBlob(1, s.sString);
        get_signature_by_index->setBlob(2, s.rString);
        std::unique_ptr<DBResult> result = get_signature_by_index->execute();
        return result->next();
    }catch (exception &e){
        syslog(LOG_CRIT, "get_signature_by_index FAILED, there may be a double signature in the database! - %s", e.what());
        return false;
    }
}

void UNPACKER_DBManager::UpdateSignatureIssuingFingerprint() {
    try{
        update_issuing_fingerprint->execute();
        syslog(LOG_DEBUG, "update_issuing_fingerprint DONE");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::UpdateSignatureIssuingUsername() {
    try{
        update_issuing_username->execute();
        syslog(LOG_DEBUG, "update_issuing_username DONE");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_username FAILED, the issuingUsername of the signature will not be inserted! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::UpdateIsExpired() {
    try{
        execute_query("COMMIT");
        update_expired->execute();
        syslog(LOG_DEBUG, "update_expired_stmt DONE");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_expired_stmt FAILED, the Signatures are not up to date checked for expiration! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::UpdateIsRevoked() {
    try{
        execute_query("COMMIT");
        //update_revoked_1->execute();
        update_revoked_2->execute();
        syslog(LOG_DEBUG, "update_revoked DONE");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_revoked FAILED, the revocation effect on Signatures will be not up to date! - %s",
                          e.what());
    }
}


void UNPACKER_DBManager::UpdateIsValid() {
    try{
        execute_query("COMMIT");
        update_valid->execute();
        syslog(LOG_DEBUG, "update_valid DONE");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_valid FAILED, the validity of Signatures will be not up to date! - %s",
                          e.what());
    }
}

}
}
