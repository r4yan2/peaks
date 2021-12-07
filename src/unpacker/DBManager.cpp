#include <sys/syslog.h>
#include <cstring>
#include <thread>

#include "DBManager.h"
#include <common/config.h>

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
    get_analyzable_cert_stmt = prepare_query("SELECT version, fingerprint, filename, origin, len "
                                         "FROM gpg_keyserver WHERE is_unpacked = 0 LIMIT ?");
    
    get_signature_by_index = prepare_query("SELECT id "
                                         "FROM Signatures WHERE r = (?) and s = (?)");
    
    insert_error_comments = prepare_query("INSERT INTO Unpacker_errors "
                                         "(version, fingerprint, error) VALUES (?, ?, ?);");
    
    set_key_not_analyzable = prepare_query("UPDATE gpg_keyserver "
                                         "SET is_unpacked = -1 WHERE version = (?) and fingerprint = unhex(?)");

    set_unpacking_status_stmt = prepare_query("UPDATE gpg_keyserver SET is_unpacked = 3 WHERE version = (?) and fingerprint = (?)");
    
    update_issuing_fingerprint = prepare_query("UPDATE Signatures INNER JOIN Pubkey on issuingKeyId = KeyId SET issuingFingerprint = fingerprint where isnull(issuingFingerprint) and issuingKeyId = KeyId;");
    update_issuing_username = prepare_query("UPDATE Signatures INNER JOIN UserID on issuingFingerprint = fingerprint SET issuingUsername = name where isnull(issuingUsername) and issuingFingerprint = fingerprint;");
    update_expired = prepare_query("UPDATE Signatures SET isExpired = 1 WHERE expirationTime < NOW();");
    update_valid = prepare_query("UPDATE Signatures as s1 SET s1.isValid = -1 WHERE s1.isExpired = 1 or isRevoked = 1;");
    update_revoked_1 = prepare_query("INSERT IGNORE INTO revocationSignatures select issuingKeyId, "
                  "signedFingerprint, signedUsername FROM Signatures WHERE isRevocation = 1;");
    update_revoked_2 = prepare_query("UPDATE Signatures INNER JOIN revocationSignatures on (Signatures.issuingKeyId = revocationSignatures.issuingKeyId and Signatures.signedFingerprint = revocationSignatures.signedFingerprint and Signatures.signedUsername = revocationSignatures.signedUsername) set isRevoked = 1, isValid = -1 where isRevoked = 0 and isRevocation = 0;");
    commit = prepare_query("COMMIT;");

}


UNPACKER_DBManager::~UNPACKER_DBManager(){
    closeCSVFiles();
};

vector<DBStruct::gpg_keyserver_data> UNPACKER_DBManager::get_certificates(const unsigned long &l) {
    vector<DBStruct::gpg_keyserver_data> certificates;
    get_analyzable_cert_stmt->setString(1, to_string(l));
    std::unique_ptr<DBResult> result = get_analyzable_cert_stmt->execute();
    while(result->next()){
        DBStruct::gpg_keyserver_data tmp_field = {
                .version = result->getInt("version"),
                .fingerprint = result->getString("fingerprint"),
                .filename = result->getString("filename"),
                .origin = result->getInt("origin"),
                .len = result->getInt("len")
        };
        tmp_field.certificate = get_certificate_from_filestore(tmp_field.filename, tmp_field.origin, tmp_field.len);
        certificates.push_back(tmp_field);
    }
    return certificates;
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

void UNPACKER_DBManager::set_as_not_analyzable(const int &version, const string &fingerprint, const string &comment) {
    try{
        insert_error_comments->setInt(1, version);
        insert_error_comments->setString(2, fingerprint);
        insert_error_comments->setString(3, comment);
        insert_error_comments->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "insert_error_comments FAILED, the key will not have some comments - %s", e.what());
    }

    try{
        set_key_not_analyzable->setInt(1, version);
        string fp;
        if (version < 4){
            fp = hexlify(fingerprint) + "00000000";
        }else{
            fp = hexlify(fingerprint);
        }
        set_key_not_analyzable->setString(2, fp);
        set_key_not_analyzable->execute();

    }catch (exception &e){
        syslog(LOG_CRIT, "set_key_not_analyzable FAILED, the key will result not UNPACKED in the database! - %s", e.what());
    }
}

void UNPACKER_DBManager::write_unpacked_csv(const OpenPGP::Key::Ptr &key, const DBStruct::Unpacker_errors &mod){
    try{
        ostringstream f;
        f << '"' << to_string(key->version()) << "\",";
        f << '"' << hexlify(key->fingerprint()) << "\",";
        if (mod.modified){
            f << '"' << "2" << "\",";
        }else{
            f << '"' << "1" << "\",";
        }
        f << "\n";
        file_list.at(Utils::TABLES::UNPACKED)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_unpacked_csv FAILED, the key will result not UNPACKED in the database! - %s", e.what());
    }
}

void UNPACKER_DBManager::write_pubkey_csv(const DBStruct::pubkey &pubkey) {
    try{
        ostringstream f;
        f << '"' << pubkey.keyId << "\",";
        f << '"' << pubkey.version << "\",";
        f << '"' << hexlify(pubkey.fingerprint) << "\",";
        f << '"' << hexlify(pubkey.priFingerprint) << "\",";
        f << '"' << pubkey.pubAlgorithm << "\",";
        f << '"' << pubkey.creationTime << "\",";
        f << '"' << pubkey.expirationTime << "\",";
        for (const auto &v: pubkey.algValue){
            f << '"' << hexlify(v) << "\",";
        }
        f << '"' << pubkey.curve<< "\",";
        f << "\n";
        file_list.at(Utils::TABLES::PUBKEY)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_pubkey_csv FAILED, the key not have the results of the unpacking in the database! - %s", e.what());
    }
}

void UNPACKER_DBManager::write_userID_csv(const DBStruct::userID &uid) {
    try{
        ostringstream f;
        f << '"' << uid.ownerkeyID << "\",";
        f << '"' << hexlify(uid.fingerprint) << "\",";
        f << '"' << uid.name << "\",";
        f << "\n";
        file_list.at(Utils::TABLES::USERID)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userID_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}


void UNPACKER_DBManager::write_userAttributes_csv(const DBStruct::userAtt &ua) {
    try{
        ostringstream f;
        f << '"' << to_string(ua.id) << "\",";
        f << '"' << hexlify(ua.fingerprint) << "\",";
        f << '"' << ua.name << "\",";
        f << '"' << ua.encoding << "\",";
        f << '"' << hexlify(ua.image) << "\",";
        f << "\n";
        file_list.at(Utils::TABLES::USER_ATTRIBUTES)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userAttributes_csv FAILED, the UserID not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::write_signature_csv(const DBStruct::signatures &ss) {
    try{
        ostringstream f;
        f << '"' << ss.type << "\",";
        f << '"' << ss.pubAlgorithm << "\",";
        f << '"' << ss.hashAlgorithm << "\",";
        f << '"' << ss.version << "\",";
        f << '"' << ss.issuingKeyId << "\",";
        f << '"' << ss.signedKeyId << "\",";
        f << '"' << hexlify(ss.issuingFingerprint) << "\",";
        f << '"' << hexlify(ss.signedFingerprint) << "\",";
        f << '"' << ss.signedUsername << "\",";
        f << '"' << ss.issuingUsername << "\",";
        f << '"' << ss.uatt_id << "\",";
        f << '"' << ss.regex << "\",";
        f << '"' << ss.creationTime << "\",";
        f << '"' << ss.expirationTime << "\",";
        f << '"' << hexlify(ss.rString) << "\",";
        f << '"' << hexlify(ss.sString) << "\",";
        f << '"' << hexlify(ss.flags) << "\",";
        f << '"' << hexlify(ss.hashHeader) << "\",";
        f << '"' << hexlify(ss.signedHash) << "\",";
        f << '"' << ss.hashMismatch << "\",";
        f << '"' << ss.keyExpirationTime << "\",";
        f << '"' << ss.revocationCode << "\",";
        f << '"' << ss.revocationReason << "\",";
        f << '"' << ss.revocationSigId << "\",";
        f << '"' << ss.isRevocable << "\",";
        f << '"' << ss.isExportable << "\",";
        f << '"' << ss.isExpired << "\",";
        f << '"' << ss.isRevocation << "\",";
        f << "\n";
        file_list.at(Utils::TABLES::SIGNATURE)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::write_self_signature_csv(const DBStruct::signatures &ss) {
    try{
        ostringstream f;
        f << '"' << ss.type << "\",";
        f << '"' << ss.pubAlgorithm << "\",";
        f << '"' << ss.hashAlgorithm << "\",";
        f << '"' << ss.version << "\",";
        f << '"' << ss.issuingKeyId << "\",";
        f << '"' << hexlify(ss.issuingFingerprint) << "\",";
        f << '"' << hexlify(ss.preferedHash) << "\",";
        f << '"' << hexlify(ss.preferedCompression) << "\",";
        f << '"' << hexlify(ss.preferedSymmetric) << "\",";
        f << '"' << ss.trustLevel << "\",";
        f << '"' << ss.keyExpirationTime << "\",";
        f << '"' << ss.isPrimaryUserId << "\",";
        f << '"' << ss.signedUsername << "\",";
        f << "\n";
        file_list.at(Utils::TABLES::SELF_SIGNATURE)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_self_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::write_unpackerErrors_csv(const DBStruct::Unpacker_errors &mod){
    try{
        ostringstream f;
        for (const auto &c: mod.comments){
            f << '"' << mod.version << "\",";
            f << '"' << hexlify(mod.fingerprint) << "\"";
            f << '"' << c << "\",";
            f << "\n";
        }
        file_list.at(Utils::TABLES::UNPACKER_ERRORS)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_unpackerErrors_csv FAILED, the error of the unpacking will not be in the database! - %s",
                          e.what());
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
        commit->execute();
        update_expired->execute();
        syslog(LOG_DEBUG, "update_expired_stmt DONE");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_expired_stmt FAILED, the Signatures are not up to date checked for expiration! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::UpdateIsRevoked() {
    try{
        commit->execute();
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
        commit->execute();
        update_valid->execute();
        syslog(LOG_DEBUG, "update_valid DONE");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_valid FAILED, the validity of Signatures will be not up to date! - %s",
                          e.what());
    }
}

}
}
