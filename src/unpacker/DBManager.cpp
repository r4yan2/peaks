#include <sys/syslog.h>
#include <cstring>
#include <thread>

#include "DBManager.h"

using namespace peaks::common;
using namespace std;

namespace peaks{
namespace unpacker{

UNPACKER_DBManager::UNPACKER_DBManager(const DBSettings &settings_):DBManager(settings_){
    prepare_queries();
}

UNPACKER_DBManager::UNPACKER_DBManager(const std::shared_ptr<UNPACKER_DBManager> & dbm):DBManager(dbm->get_settings()){
    prepare_queries();
}

void UNPACKER_DBManager::prepare_queries(){
    //con->createStatement()->execute("set sql_log_bin = 0;");
    //con->createStatement()->execute("set foreign_key_checks = 0;");

    // Create prepared Statements
    get_analyzable_cert_stmt = prepare_query("SELECT version, fingerprint, certificate "
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

std::pair<std::string, std::string> UNPACKER_DBManager::insert_pubkey_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE Pubkey FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' "
                                     "(keyId,version,@hexfingerprint,@hexpriFingerprint,pubAlgorithm,creationTime,@vexpirationTime,"
                                     "@hexe,@hexn,@hexp,@hexq,@hexg,@hexy,curveOID) SET fingerprint = UNHEX(@hexfingerprint),"
                                     "PriFingerprint = UNHEX(@hexpriFingerprint), e = UNHEX(@hexe), n = UNHEX(@hexn),"
                                     "p = UNHEX(@hexp), q = UNHEX(@hexq), g = UNHEX(@hexg), y = UNHEX(@hexy), "
                                     "expirationTime = nullif(@vexpirationTime, '');");

std::pair<std::string, std::string> UNPACKER_DBManager::insert_signature_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE Signatures FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' "
                                     "(type,pubAlgorithm,hashAlgorithm,version,issuingKeyId,signedKeyId,"
                                     "@hexissuingFingerprint,@hexsignedFingerprint,@vsignedUsername,@vissuingUsername,"
                                     "@vsign_Uatt_id,@vregex,creationTime,"
                                     "@vexpirationTime,@hexr,@hexs,@hexflags,@hexhashHeader,@hexsignedHash,hashMismatch,@vkeyExpirationTime,"
                                     "revocationCode,revocationReason,revocationSigId,isRevocable,"
                                     "isExportable,isExpired,isRevocation) "
                                     "SET issuingFingerprint = UNHEX(nullif(@hexissuingFingerprint, '')), "
                                     "signedUsername = nullif(FROM_BASE64(@vsignedUsername), ''), sign_Uatt_id = nullif(@vsign_Uatt_id, ''), "
                                     "signedFingerprint = UNHEX(@hexsignedFingerprint), r = UNHEX(@hexr), regex = nullif(@vregex, ''), "
                                     "s = UNHEX(@hexs), hashHeader = UNHEX(@hexhashHeader), issuingUsername = nullif(FROM_BASE64(@vissuingUsername), ''), "
                                     "signedHash = UNHEX(@hexsignedHash), expirationTime = nullif(@vexpirationTime, ''), "
                                     "keyExpirationTime = nullif(@vkeyExpirationTime, ''), flags = nullif(UNHEX(@hexflags), '');");

std::pair<std::string, std::string> UNPACKER_DBManager::insert_userID_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE UserID FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' (ownerkeyID,@hexfingerprint,@base64name) "
                                     "SET fingerprint = UNHEX(@hexfingerprint), name = FROM_BASE64(@base64name);");

std::pair<std::string, std::string> UNPACKER_DBManager::insert_self_signature_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE selfSignaturesMetadata FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' "
                                     "(type,pubAlgorithm,hashAlgorithm,version,issuingKeyId,@hexissuingFingerprint,"
                                     "@hexpreferedHash,@hexpreferedCompression,@hexpreferedSymmetric,trustLevel,@vkeyExpirationTime,"
                                     "isPrimaryUserId,@base64signedUserId) SET issuingFingerprint = UNHEX(@hexissuingFingerprint), "
                                     "preferedSymmetric = UNHEX(@hexpreferedSymmetric), preferedCompression = UNHEX(@hexpreferedCompression), "
                                     "preferedHash = UNHEX(@hexpreferedHash), keyExpirationTime = nullif(@vkeyExpirationTime, ''), signedUserId = FROM_BASE64(@base64SignedUserId);");

std::pair<std::string, std::string> UNPACKER_DBManager::insert_userAtt_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE UserAttribute FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' (id,@hexfingerprint,@base64name,encoding,@heximage) "
                                     "SET fingerprint = UNHEX(@hexfingerprint), name = FROM_BASE64(@base64name), image = UNHEX(@heximage);");

std::pair<std::string, std::string> UNPACKER_DBManager::insert_unpackerErrors_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE Unpacker_errors FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' (version, @hexfingerprint, error) SET fingerprint = UNHEX(@hexfingerprint);");

std::pair<std::string, std::string> UNPACKER_DBManager::insert_unpacked_stmt = make_pair<string, string>(
                    "LOAD DATA LOCAL INFILE '", "' IGNORE INTO TABLE tmp_unpacker FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
                    "LINES STARTING BY '.' TERMINATED BY '\\n' (version,@hexfingerprint,unpacked) SET fingerprint = UNHEX(@hexfingerprint);");

std::string UNPACKER_DBManager::create_unpacker_tmp_table = "CREATE TEMPORARY TABLE tmp_unpacker (version tinyint, fingerprint binary(20), unpacked tinyint);";
std::string UNPACKER_DBManager::update_gpg_keyserver = "UPDATE gpg_keyserver INNER JOIN tmp_unpacker ON tmp_unpacker.version = gpg_keyserver.version AND tmp_unpacker.fingerprint = gpg_keyserver.fingerprint SET gpg_keyserver.is_unpacked = tmp_unpacker.unpacked;";
std::string UNPACKER_DBManager::drop_unpacker_tmp_table = "DROP TEMPORARY TABLE tmp_unpacker;";

UNPACKER_DBManager::~UNPACKER_DBManager(){
    for (auto &it: file_list){
        it.second.close();
    }
};

vector<DBStruct::gpg_keyserver_data> UNPACKER_DBManager::get_certificates(const unsigned long &l) {
    vector<DBStruct::gpg_keyserver_data> certificates;
    get_analyzable_cert_stmt->setString(1, to_string(l));
    std::unique_ptr<DBResult> result = get_analyzable_cert_stmt->execute();
    while(result->next()){
        DBStruct::gpg_keyserver_data tmp_field = {
                .version = result->getInt("version"),
                .fingerprint = result->getString("fingerprint"),
                .certificate = result->getString("certificate")
        };
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
        ostream &f = file_list.at(Utils::UNPACKED);
        f << '.' << '"' << to_string(key->version()) << "\",";
        f << '"' << hexlify(key->fingerprint()) << "\",";
        if (mod.modified){
            f << '"' << "2" << "\",";
        }else{
            f << '"' << "1" << "\",";
        }
        f << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_unpacked_csv FAILED, the key will result not UNPACKED in the database! - %s", e.what());
    }
}

void UNPACKER_DBManager::write_pubkey_csv(const DBStruct::pubkey &pubkey) {
    try{
        ostream &f = file_list.at(Utils::PUBKEY);
        f << '.' << '"' << pubkey.keyId << "\",";
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
    }catch (exception &e){
        syslog(LOG_CRIT, "write_pubkey_csv FAILED, the key not have the results of the unpacking in the database! - %s", e.what());
    }
}

void UNPACKER_DBManager::write_userID_csv(const DBStruct::userID &uid) {
    try{
        ostream &f = file_list.at(Utils::USERID);
        f << '.' << '"' << uid.ownerkeyID << "\",";
        f << '"' << hexlify(uid.fingerprint) << "\",";
        f << '"' << uid.name << "\",";
        f << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userID_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}


void UNPACKER_DBManager::write_userAttributes_csv(const DBStruct::userAtt &ua) {
    try{
        ostream &f = file_list.at(Utils::USER_ATTRIBUTES);
        f << '.' << '"' << to_string(ua.id) << "\",";
        f << '"' << hexlify(ua.fingerprint) << "\",";
        f << '"' << ua.name << "\",";
        f << '"' << ua.encoding << "\",";
        f << '"' << hexlify(ua.image) << "\",";
        f << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userAttributes_csv FAILED, the UserID not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::write_signature_csv(const DBStruct::signatures &ss) {
    try{
        ostream &f = file_list.at(Utils::SIGNATURE);
        f << '.' << '"' << ss.type << "\",";
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
    }catch (exception &e){
        syslog(LOG_CRIT, "write_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::write_self_signature_csv(const DBStruct::signatures &ss) {
    try{
        ostream &f = file_list.at(Utils::SELF_SIGNATURE);
        f << '.' << '"' << ss.type << "\",";
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
    }catch (exception &e){
        syslog(LOG_CRIT, "write_self_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::write_unpackerErrors_csv(const DBStruct::Unpacker_errors &mod){
    try{
        ostream &f = file_list.at(Utils::UNPACKER_ERRORS);
        for (const auto &c: mod.comments){
            f << '.' << '"' << mod.version << "\",";
            f << '"' << hexlify(mod.fingerprint) << "\"";
            f << '"' << c << "\",";
            f << "\n";
        }
    }catch (exception &e){
        syslog(LOG_CRIT, "write_unpackerErrors_csv FAILED, the error of the unpacking will not be in the database! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::insertCSV(const string &f){
    std::vector<std::string> fullpath, filename;
    boost::split(fullpath, f, boost::is_any_of("/"));
    for (auto const &x: Utils::FILENAME){
        if (Utils::hasEnding(fullpath.back(), x.second)){
            return insertCSV(f, x.first);
        }
    }
}

void UNPACKER_DBManager::insertCSV(const string &f, const unsigned int &table){
    check_database_connection();
    unsigned int backoff = 1;
    unsigned int num_retries = 0;
    std::string statement;
    switch (table){
        case Utils::PUBKEY:
            statement = insert_pubkey_stmt.first + f + insert_pubkey_stmt.second;
            break;
        case Utils::SIGNATURE:
            statement = insert_signature_stmt.first + f + insert_signature_stmt.second;
            break;
        case Utils::SELF_SIGNATURE:
            statement = insert_self_signature_stmt.first + f + insert_self_signature_stmt.second;
            break;
        case Utils::USERID:
            statement = insert_userID_stmt.first + f + insert_userID_stmt.second;
            break;
        case Utils::USER_ATTRIBUTES:
            statement = insert_userAtt_stmt.first + f + insert_userAtt_stmt.second;
            break;
        case Utils::UNPACKED:
            execute_query(create_unpacker_tmp_table);
            statement = insert_unpacked_stmt.first + f + insert_unpacked_stmt.second;
            break;
        case Utils::UNPACKER_ERRORS:
            statement = insert_unpackerErrors_stmt.first + f + insert_unpackerErrors_stmt.second;
            break;
    }

    do{
        try{
            execute_query(statement);
            if (table == Utils::UNPACKED){
                execute_query(update_gpg_keyserver);
            }
            backoff = 0;
        }catch(exception &e){
            num_retries += 1;
            unsigned int sleep_seconds = (backoff << num_retries) * 60 ;
            switch (table){
                case Utils::PUBKEY:
                        syslog(LOG_CRIT, "insert_pubkey_stmt FAILED, the key not have the results of the unpacking in the database! - %s",
                                          e.what());
                        break;
                case Utils::SIGNATURE:
                        syslog(LOG_CRIT, "insert_signature_stmt FAILED, the signature not have the results of the unpacking in the database! - %s",
                                          e.what());
                        break;
                case Utils::SELF_SIGNATURE:
                        syslog(LOG_CRIT, "insert_self_signature_stmt FAILED, the signature not have the results of the unpacking in the database! - %s",
                                          e.what());
                        break;
                case Utils::USERID:
                        syslog(LOG_CRIT, "insert_userID_stmt FAILED, the UserID not have the results of the unpacking in the database! - %s",
                                          e.what());
                        break;
                case Utils::USER_ATTRIBUTES:
                        syslog(LOG_CRIT, "insert_userAtt_stmt FAILED, the UserID not have the results of the unpacking in the database! - %s",
                                          e.what());
                        break;
                case Utils::UNPACKED:
                        syslog(LOG_CRIT, "insert_unpacked_stmt FAILED, the key will result NOT UNPACKED in the database! - %s",
                                          e.what());
                        execute_query(drop_unpacker_tmp_table);
                        break;
                case Utils::UNPACKER_ERRORS:
                        syslog(LOG_CRIT, "insert_unpackerErrors_stmt FAILED, the error of the unpacking will not be in the database! - %s",
                                          e.what());
                        break;
            }
            this_thread::sleep_for(std::chrono::seconds{sleep_seconds});
        }
    } while (backoff > 0 && num_retries < 5);
    if (backoff > 0){
        Utils::put_in_error(settings.error_folder, f, table);
    }
    try{
        remove(f.c_str());
    } catch (std::exception &e){
        syslog(LOG_CRIT, "File deleting FAILED, the following file MUST be deleted manually: %s. Error: %s", f.c_str(), e.what());

    }
}

void UNPACKER_DBManager::UpdateSignatureIssuingFingerprint() {
    try{
        update_issuing_fingerprint->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::UpdateSignatureIssuingUsername() {
    try{
        update_issuing_username->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_username FAILED, the issuingUsername of the signature will not be inserted! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::UpdateIsExpired() {
    try{
        commit->execute();
        update_expired->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "update_expired_stmt FAILED, the Signatures are not up to date checked for expiration! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::UpdateIsRevoked() {
    try{
        commit->execute();
        update_revoked_2->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "update_revoked FAILED, the revocation effect on Signatures will be not up to date! - %s",
                          e.what());
    }
}


void UNPACKER_DBManager::UpdateIsValid() {
    try{
        commit->execute();
        update_valid->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "update_valid FAILED, the validity of Signatures will be not up to date! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::openCSVFiles(){
    // Open files
    for (const auto &it: Utils::FILENAME){
        UNPACKER_DBManager::file_list.insert(std::pair<unsigned int, ofstream>(
                it.first,
                ofstream(Utils::get_file_name(settings.tmp_folder, it.first, this_thread::get_id()), ios_base::app)));
    }
}

}
}
