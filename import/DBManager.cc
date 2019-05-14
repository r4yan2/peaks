#include <sys/syslog.h>
#include <cstring>
#include <sstream>
#include <Misc/mpi.h>
#include <thread>

#include "DBManager.h"
#include <boost/program_options.hpp>

using namespace std;

IMPORT_DBManager::IMPORT_DBManager(const DBSettings & settings_, const ImportFolders & folders_):
    DBManager(settings_),
    folders(folders_)
{
    prepare_queries();
}

IMPORT_DBManager::IMPORT_DBManager(const std::shared_ptr<IMPORT_DBManager> & dbm_):
    DBManager(dbm_->get_settings()),
    folders(dbm_->get_folders())
{
    prepare_queries();
}

void IMPORT_DBManager::prepare_queries() {
    get_signature_by_index = prepare_query("SELECT id "
                                     "FROM Signatures WHERE r = (?) and s = (?)");
}

    std::pair<std::string, std::string> IMPORT_DBManager::insert_brokenKey_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE broken_keys FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' "
                                     "(@hexcertificate,log) SET certificate = UNHEX(@hexcertificate);");


    std::pair<std::string, std::string> IMPORT_DBManager::insert_pubkey_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE Pubkey FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' "
                                     "(keyId,version,@hexfingerprint,@hexpriFingerprint,pubAlgorithm,creationTime,@vexpirationTime,"
                                     "@hexe,@hexn,@hexp,@hexq,@hexg,@hexy,curveOID) SET fingerprint = UNHEX(@hexfingerprint),"
                                     "priFingerprint = UNHEX(@hexpriFingerprint), e = UNHEX(@hexe), n = UNHEX(@hexn),"
                                     "p = UNHEX(@hexp), q = UNHEX(@hexq), g = UNHEX(@hexg), y = UNHEX(@hexy), "
                                     "expirationTime = nullif(@vexpirationTime, '');");

    std::pair<std::string, std::string> IMPORT_DBManager::insert_signature_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE Signatures FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
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
                                     "keyExpirationTime = nullif(@vkeyExpirationTime, ''), flags = UNHEX(@hexflags);");

    std::pair<std::string, std::string> IMPORT_DBManager::insert_self_signature_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE selfSignaturesMetadata FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' "
                                     "(type,pubAlgorithm,hashAlgorithm,version,issuingKeyId,@hexissuingFingerprint,"
                                     "@hexpreferedHash,@hexpreferedCompression,@hexpreferedSymmetric,trustLevel,@vkeyExpirationTime,"
                                     "isPrimaryUserId,@base64signedUserId) SET issuingFingerprint = UNHEX(@hexissuingFingerprint), "
                                     "preferedSymmetric = UNHEX(@hexpreferedSymmetric), preferedCompression = UNHEX(@hexpreferedCompression), "
                                     "preferedHash = UNHEX(@hexpreferedHash), keyExpirationTime = nullif(@vkeyExpirationTime, ''), signedUserID = FROM_BASE64(@base64signedUserID);");

    std::pair<std::string, std::string> IMPORT_DBManager::insert_userID_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE UserID FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' (ownerkeyID,@hexfingerprint,@base64name) "
                                     "SET fingerprint = UNHEX(@hexfingerprint), name = FROM_BASE64(@base64name);");

    std::pair<std::string, std::string> IMPORT_DBManager::insert_userAtt_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE UserAttribute FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' (id,@hexfingerprint,@base64name,encoding,@heximage) "
                                     "SET fingerprint = UNHEX(@hexfingerprint), name = FROM_BASE64(@base64name), image = UNHEX(@heximage);");

    std::pair<std::string, std::string> IMPORT_DBManager::insert_unpackerErrors_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE Unpacker_errors FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' (version,@hexfingerprint,error) "
                                     "SET fingerprint = UNHEX(@hexfingerprint);");

    std::pair<std::string, std::string> IMPORT_DBManager::insert_certificate_stmt = make_pair<string, string>(
            "LOAD DATA LOCAL INFILE '", "' IGNORE INTO TABLE gpg_keyserver FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
            "LINES STARTING BY '.' TERMINATED BY '\\n' (version,ID,@hexfingerprint,@hexcertificate,hash,is_unpacked,error_code) "
            "SET fingerprint = UNHEX(@hexfingerprint), certificate = UNHEX(@hexcertificate), is_synchronized = 1");

IMPORT_DBManager::~IMPORT_DBManager(){
    for (auto &it: file_list){
        if (it.second.is_open()){
            it.second.close();
        }
    }
};

ImportFolders IMPORT_DBManager::get_folders(){
    return folders;
}

bool IMPORT_DBManager::existSignature(const DBStruct::signatures &s){
    std::istream *r_sign = new istringstream(s.r);
    std::istream *s_sign = new istringstream(s.s);
    try {
        get_signature_by_index->setBlob(1, r_sign);
        get_signature_by_index->setBlob(2, s_sign);
        std::unique_ptr<DBResult> result = get_signature_by_index->execute();
        delete r_sign;
        delete s_sign;
        return result->next();
    }catch (exception &e){
        syslog(LOG_CRIT, "get_signature_by_index FAILED, there may be a double signature in the database! - %s", e.what());
        delete r_sign;
        delete s_sign;
        return false;
    }
}

void IMPORT_DBManager::write_gpg_keyserver_csv(const DBStruct::gpg_keyserver_data &gpg_data, const int is_unpacked){
    try{
        ostream &f = file_list.at(Utils::CERTIFICATE);
        f << '.' << '"' << to_string(gpg_data.version) << "\",";
        f << '"' << gpg_data.ID << "\",";
        f << '"' << hexlify(gpg_data.fingerprint) << "\",";
        f << '"' << hexlify(gpg_data.certificate) << "\",";
        f << '"' << gpg_data.hash << "\",";
        f << '"' << is_unpacked << "\",";
        f << '"' << to_string(gpg_data.error_code) << "\",";
        f << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_gpg_keyserver_csv FAILED, the key will not have the certificate in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_broken_key_csv(std::ifstream &file_cert, const std::string &error){
    try{
        file_cert.clear();
        file_cert.seekg(file_cert.beg);
        std::string buffer(std::istreambuf_iterator <char> (file_cert), {});
        ostream &f = file_list.at(Utils::BROKEN_KEY);
        f << '.' << '"' << hexlify(buffer) << "\",";
        f << '"' << error << "\",";
        f << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_broken_key_csv FAILED, broken key lost! - %s", e.what());
    }
}

void IMPORT_DBManager::write_pubkey_csv(const DBStruct::pubkey &pubkey) {
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

void IMPORT_DBManager::write_userID_csv(const DBStruct::userID &uid) {
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

void IMPORT_DBManager::write_userAttributes_csv(const DBStruct::userAtt &ua) {
    try{
        ostream &f = file_list.at(Utils::USER_ATTRIBUTES);
        f << '.' << '"' << to_string(ua.id) << "\",";
        f << '"' << hexlify(ua.fingerprint) << "\",";
        f << '"' << ua.name << "\",";
        f << '"' << ua.encoding << "\",";
        f << '"' << hexlify(ua.image) << "\",";
        f << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userAttributes_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_signature_csv(const DBStruct::signatures &ss) {
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
        f << '"' << hexlify(ss.r) << "\",";
        f << '"' << hexlify(ss.s) << "\",";
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
        syslog(LOG_CRIT, "write_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_self_signature_csv(const DBStruct::signatures &ss) {
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
        syslog(LOG_CRIT, "write_self_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_unpackerErrors_csv(const DBStruct::Unpacker_errors &mod){
    try{
        ostream &f = file_list.at(Utils::UNPACKER_ERRORS);
        for (const auto &c: mod.comments){
            //f << '.' << '"' << mod.keyId << "\",";
            f << '.' << '"' << mod.version << "\",";
            f << '"' << hexlify(mod.fingerprint) << "\"";
            f << '"' << c << "\",";
            f << "\n";
        }
    }catch (exception &e){
        syslog(LOG_CRIT, "write_unpackerErrors_csv FAILED, the error of the unpacking will not be in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::insertCSV(const std::string & f, const unsigned int &table){
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
        case Utils::CERTIFICATE:
            statement = insert_certificate_stmt.first + f + insert_certificate_stmt.second;
            break;
        case Utils::BROKEN_KEY:
            statement = insert_brokenKey_stmt.first + f + insert_brokenKey_stmt.second;
            break;
        case Utils::UNPACKER_ERRORS:
            statement = insert_unpackerErrors_stmt.first + f + insert_unpackerErrors_stmt.second;
            break;
    }

    do{
        try{
            execute_query(statement);
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
                case Utils::CERTIFICATE:
                        syslog(LOG_CRIT, "insert_certificate_stmt FAILED, the key will not have the certificate in the database! - %s",
                                          e.what());
                        break;
                case Utils::BROKEN_KEY:
                        syslog(LOG_CRIT, "insert_brokenKey_stmt FAILED, the broken key will not be in the database! - %s",
                                      e.what());
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
        Utils::put_in_error(folders.error_folder, f, table);
    }
    try{
        remove(f.c_str());
    } catch (std::exception &e){
        syslog(LOG_CRIT, "File deleting FAILED, the following file MUST be deleted manually: %s. Error: %s", f.c_str(), e.what());

    }
}

void IMPORT_DBManager::UpdateSignatureIssuingFingerprint() {
    try{
        execute_query("COMMIT");
        execute_query("UPDATE Signatures INNER JOIN Pubkey on issuingKeyId = KeyId SET issuingFingerprint = fingerprint where isnull(issuingFingerprint) and issuingKeyId = KeyId;");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void IMPORT_DBManager::UpdateSignatureIssuingUsername() {
    try{
        execute_query("COMMIT");
        execute_query("UPDATE Signatures INNER JOIN key_primary_userID on "
             "issuingFingerprint = fingerprint SET issuingUsername = name WHERE issuingUsername IS NULL;");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void IMPORT_DBManager::UpdateIsExpired() {
    try{
        execute_query("COMMIT");
        execute_query("UPDATE Signatures SET isExpired = 1 WHERE expirationTime < NOW();");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void IMPORT_DBManager::UpdateIsRevoked() {
    try{
        execute_query("COMMIT");
        execute_query("INSERT IGNORE INTO revocationSignatures select issuingKeyId, "
             "signedFingerprint, signedUsername FROM Signatures WHERE isRevocation = 1;");
        execute_query("UPDATE Signatures set isRevoked = 1 where isRevoked = 0 "
             "and isRevocation = 0 and (issuingKeyId, signedFingerprint, signedUsername) in (select * from revocationSignatures);");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void IMPORT_DBManager::UpdateIsValid() {
    try{
        execute_query("COMMIT");
        execute_query("UPDATE Signatures as s1 SET s1.isValid = -1 WHERE s1.isExpired = 1 "
             "or isRevoked = 1;");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void IMPORT_DBManager::lockTables(){
    try{
        execute_query("LOCK TABLES broken_keys WRITE, gpg_keyserver WRITE, "
             "KeyStatus WRITE, Pubkey WRITE, selfSignaturesMetadata WRITE, Signatures WRITE, SignatureStatus WRITE, revocationSignatures WRITE, "
             "Unpacker_errors WRITE, UserID WRITE, Signature_no_issuing_fp WRITE, UserAttribute WRITE, key_primary_userID WRITE");
    }catch (exception &e){
        syslog(LOG_WARNING, "lock_tables_stmt FAILED, the query will be slowly! - %s",
                             e.what());
    }
}

void IMPORT_DBManager::unlockTables(){
    try{
        execute_query(("UNLOCK TABLES;"));
    }catch (exception &e){
        syslog(LOG_CRIT, "unlock_tables_stmt FAILED, the tables will remain locked! - %s",
                          e.what());
    }
}

void IMPORT_DBManager::openCSVFiles() {
    // Open files
    std::map<unsigned int, std::ofstream> file_list;
    for (const auto &it: Utils::FILENAME){
        IMPORT_DBManager::file_list.insert(std::pair<unsigned int, ofstream>(
                it.first,
                ofstream(Utils::get_file_name(folders.csv_folder, it.first, this_thread::get_id()), ios_base::app)));
    }
}
