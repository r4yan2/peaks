#include <sys/syslog.h>
#include <cstring>
#include <sstream>
#include <thread>

#include "DBManager.h"
#include <boost/program_options.hpp>

using namespace std;

namespace peaks{
namespace import{
IMPORT_DBManager::IMPORT_DBManager(const DBSettings & settings_):
    DBManager(settings_)
{
	tables = {
        {1, "gpg_keyserver"},
	    {2, "Pubkey"},
	    {3, "Signatures"},
	    {4, "selfSignaturesMetadata"},
	    {5, "UserAttribute"}, 
	    {6, "Unpacker_errors"},
	    {7, "UserID"},
	};
    prepare_queries();
}

IMPORT_DBManager::IMPORT_DBManager(const std::shared_ptr<IMPORT_DBManager> & dbm_):
    IMPORT_DBManager(dbm_->get_settings())
{}

void IMPORT_DBManager::prepare_queries() {
    get_signature_by_index = prepare_query("SELECT id "
                                     "FROM Signatures WHERE r = (?) and s = (?)");
}


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
            "SET fingerprint = UNHEX(@hexfingerprint), certificate = COMPRESS(UNHEX(@hexcertificate)), is_synchronized = 1");

IMPORT_DBManager::~IMPORT_DBManager()
{}

bool IMPORT_DBManager::existSignature(const DBStruct::signatures &s){
    std::istream *r_sign = new istringstream(s.rString);
    std::istream *s_sign = new istringstream(s.sString);
    try {
        get_signature_by_index->setBlob(1, r_sign);
        get_signature_by_index->setBlob(2, s_sign);
        std::unique_ptr<DBResult> result = get_signature_by_index->execute();
        return result->next();
    }catch (exception &e){
        syslog(LOG_CRIT, "get_signature_by_index FAILED, there may be a double signature in the database! - %s", e.what());
        return false;
    }
}

void IMPORT_DBManager::drop_index_gpg_keyserver(){
	execute_query("ALTER TABLE gpg_keyserver DROP INDEX ID;");
	execute_query("ALTER TABLE gpg_keyserver DROP INDEX HASH;");
}

void IMPORT_DBManager::build_index_gpg_keyserver(){
	execute_query("ALTER TABLE gpg_keyserver ADD INDEX `ID` (`ID`,`fingerprint`) USING BTREE;");
	execute_query("ALTER TABLE gpg_keyserver ADD INDEX `HASH` (`hash` ASC);");
}

void IMPORT_DBManager::write_gpg_keyserver_csv(const DBStruct::gpg_keyserver_data &gpg_data, const int is_unpacked){
    try{
        ostringstream f;
        f << '.' << '"' << to_string(gpg_data.version) << "\",";
        f << '"' << gpg_data.ID << "\",";
        f << '"' << hexlify(gpg_data.fingerprint) << "\",";
        f << '"' << hexlify(gpg_data.certificate) << "\",";
        f << '"' << gpg_data.hash << "\",";
        f << '"' << is_unpacked << "\",";
        f << '"' << to_string(gpg_data.error_code) << "\",";
        f << "\n";
		file_list.at(Utils::CERTIFICATE)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_gpg_keyserver_csv FAILED, the key will not have the certificate in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_pubkey_csv(const DBStruct::pubkey &pubkey) {
    try{
        ostringstream f;
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
		file_list.at(Utils::PUBKEY)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_pubkey_csv FAILED, the key not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_userID_csv(const DBStruct::userID &uid) {
    try{
        ostringstream f;
        f << '.' << '"' << uid.ownerkeyID << "\",";
        f << '"' << hexlify(uid.fingerprint) << "\",";
        f << '"' << uid.name << "\",";
        f << "\n";
		file_list.at(Utils::USERID)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userID_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_userAttributes_csv(const DBStruct::userAtt &ua) {
    try{
        ostringstream f;
        f << '.' << '"' << to_string(ua.id) << "\",";
        f << '"' << hexlify(ua.fingerprint) << "\",";
        f << '"' << ua.name << "\",";
        f << '"' << ua.encoding << "\",";
        f << '"' << hexlify(ua.image) << "\",";
        f << "\n";
		file_list.at(Utils::USER_ATTRIBUTES)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userAttributes_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_signature_csv(const DBStruct::signatures &ss) {
    try{
        ostringstream f;
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
		file_list.at(Utils::SIGNATURE)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_self_signature_csv(const DBStruct::signatures &ss) {
    try{
        ostringstream f;
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
		file_list.at(Utils::SELF_SIGNATURE)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_self_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_unpackerErrors_csv(const DBStruct::Unpacker_errors &mod){
    try{
		for (const auto &c: mod.comments){
        	ostringstream f;
            f << '.' << '"' << mod.version << "\",";
            f << '"' << hexlify(mod.fingerprint) << "\"";
            f << '"' << c << "\",";
            f << "\n";
			file_list.at(Utils::UNPACKER_ERRORS)->write(f.str());
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

void IMPORT_DBManager::openCSVFiles() {
    // Open files
    for (const auto &it: Utils::FILENAME)
		IMPORT_DBManager::file_list[it.first] = make_shared<SynchronizedFile>(Utils::get_file_name(settings.tmp_folder, it.first));
}

}
}
