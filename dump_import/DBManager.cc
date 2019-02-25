#include <sys/syslog.h>
#include <cstring>
#include <sstream>
#include <Misc/mpi.h>
#include <thread>

#include "DBManager.h"
#include <boost/program_options.hpp>


using namespace sql;
using namespace std;


// Database connector initialization

DUMPIMPORT_DBManager::DUMPIMPORT_DBManager(const Dumpimport_DBConfig &settings_) {
    DUMPIMPORT_DBManager::driver = get_driver_instance();
    settings = settings_;
}

void DUMPIMPORT_DBManager::init_database_connection() {
    DUMPIMPORT_DBManager::con = shared_ptr<Connection>(driver->connect(settings.db_host, settings.db_user, settings.db_password));
    // Connect to the MySQL keys database
    con->setSchema(settings.db_database);

    //con->createStatement()->execute("set sql_log_bin = 0;");
    con->createStatement()->execute("set foreign_key_checks = 0;");

    // Create prepared Statements
    get_signature_by_index = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT id "
                                     "FROM Signatures WHERE r = (?) and s = (?)"));

    insert_brokenKey_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE broken_keys FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' "
                                     "(@hexcertificate,log) SET certificate = UNHEX(@hexcertificate);");


    insert_pubkey_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE Pubkey FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' "
                                     "(keyId,version,@hexfingerprint,@hexpriFingerprint,pubAlgorithm,creationTime,@vexpirationTime,"
                                     "@hexe,@hexn,@hexp,@hexq,@hexg,@hexy,curveOID) SET fingerprint = UNHEX(@hexfingerprint),"
                                     "priFingerprint = UNHEX(@hexpriFingerprint), e = UNHEX(@hexe), n = UNHEX(@hexn),"
                                     "p = UNHEX(@hexp), q = UNHEX(@hexq), g = UNHEX(@hexg), y = UNHEX(@hexy), "
                                     "expirationTime = nullif(@vexpirationTime, '');");

    insert_signature_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
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

    insert_self_signature_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE selfSignaturesMetadata FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' "
                                     "(type,pubAlgorithm,hashAlgorithm,version,issuingKeyId,@hexissuingFingerprint,"
                                     "@hexpreferedHash,@hexpreferedCompression,@hexpreferedSymmetric,trustLevel,@vkeyExpirationTime,"
                                     "isPrimaryUserId,@base64signedUserId) SET issuingFingerprint = UNHEX(@hexissuingFingerprint), "
                                     "preferedSymmetric = UNHEX(@hexpreferedSymmetric), preferedCompression = UNHEX(@hexpreferedCompression), "
                                     "preferedHash = UNHEX(@hexpreferedHash), keyExpirationTime = nullif(@vkeyExpirationTime, signedUserID = FROM_BASE64(@base64signedUserID) '');");

    insert_userID_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE UserID FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' (ownerkeyID,@hexfingerprint,@base64name,email) "
                                     "SET fingerprint = UNHEX(@hexfingerprint), name = FROM_BASE64(@base64name);");

    insert_userAtt_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE UserAttribute FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' (id,@hexfingerprint,@base64name,encoding,@heximage) "
                                     "SET fingerprint = UNHEX(@hexfingerprint), name = FROM_BASE64(@base64name), image = UNHEX(@heximage);");

    insert_unpackerErrors_stmt = make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE Unpacker_errors FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
                                     "LINES STARTING BY '.' TERMINATED BY '\\n' (version,@hexfingerprint,error) "
                                     "SET fingerprint = UNHEX(@hexfingerprint);");

    insert_certificate_stmt = make_pair<string, string>(
            "LOAD DATA LOCAL INFILE '", "' IGNORE INTO TABLE gpg_keyserver FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
            "LINES STARTING BY '.' TERMINATED BY '\\n' (version,ID,@hexfingerprint,@hexcertificate,hash,is_unpacked,error_code) "
            "SET fingerprint = UNHEX(@hexfingerprint), certificate = UNHEX(@hexcertificate), is_synchronized = 1;");

}

DUMPIMPORT_DBManager::~DUMPIMPORT_DBManager(){
    for (auto &it: file_list){
        if (it.second.is_open()){
            it.second.close();
        }
    }
    driver->threadEnd();
};

bool DUMPIMPORT_DBManager::existSignature(const DBStruct::signatures &s){
    std::istream *r_sign = new istringstream(s.r);
    std::istream *s_sign = new istringstream(s.s);
    try {
        get_signature_by_index->setBlob(1, r_sign);
        get_signature_by_index->setBlob(2, s_sign);
        result = shared_ptr<ResultSet>(get_signature_by_index->executeQuery());
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

void DUMPIMPORT_DBManager::write_gpg_keyserver_csv(const DBStruct::gpg_keyserver_data &gpg_data, const int is_unpacked){
    try{
        ostream &f = file_list.at(DUMP_Utils::CERTIFICATE);
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

void DUMPIMPORT_DBManager::write_broken_key_csv(std::ifstream &file_cert, const std::string &error){
    try{
        file_cert.clear();
        file_cert.seekg(file_cert.beg);
        std::string buffer(std::istreambuf_iterator <char> (file_cert), {});
        ostream &f = file_list.at(DUMP_Utils::BROKEN_KEY);
        f << '.' << '"' << hexlify(buffer) << "\",";
        f << '"' << error << "\",";
        f << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_broken_key_csv FAILED, broken key lost! - %s", e.what());
    }
}

void DUMPIMPORT_DBManager::write_pubkey_csv(const DBStruct::pubkey &pubkey) {
    try{
        ostream &f = file_list.at(DUMP_Utils::PUBKEY);
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

void DUMPIMPORT_DBManager::write_userID_csv(const DBStruct::userID &uid) {
    try{
        ostream &f = file_list.at(DUMP_Utils::USERID);
        f << '.' << '"' << uid.ownerkeyID << "\",";
        f << '"' << hexlify(uid.fingerprint) << "\",";
        f << '"' << uid.name << "\",";
        f << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userID_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}

void DUMPIMPORT_DBManager::write_userAttributes_csv(const DBStruct::userAtt &ua) {
    try{
        ostream &f = file_list.at(DUMP_Utils::USER_ATTRIBUTES);
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

void DUMPIMPORT_DBManager::write_signature_csv(const DBStruct::signatures &ss) {
    try{
        ostream &f = file_list.at(DUMP_Utils::SIGNATURE);
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

void DUMPIMPORT_DBManager::write_self_signature_csv(const DBStruct::signatures &ss) {
    try{
        ostream &f = file_list.at(DUMP_Utils::SELF_SIGNATURE);
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

void DUMPIMPORT_DBManager::write_unpackerErrors_csv(const DBStruct::Unpacker_errors &mod){
    try{
        ostream &f = file_list.at(DUMP_Utils::UNPACKER_ERRORS);
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

void DUMPIMPORT_DBManager::insertCSV(const vector<string> &files, const unsigned int &table){
    switch (table){
        case DUMP_Utils::PUBKEY:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_pubkey_stmt.first + f + insert_pubkey_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_pubkey_stmt FAILED, the key not have the results of the unpacking in the database! - %s", e.what());
                    DUMP_Utils::put_in_error(settings.error_folder, f, DUMP_Utils::PUBKEY);
                }
            }
            break;
        case DUMP_Utils::SIGNATURE:
            for (const auto &f: files){
                try{
                    string query = insert_signature_stmt.first + f + insert_signature_stmt.second;
                    shared_ptr<Statement>(con->createStatement())->execute(insert_signature_stmt.first + f + insert_signature_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_signature_stmt FAILED, the signature not have the results of the unpacking in the database! - %s",
                                      e.what());
                    DUMP_Utils::put_in_error(settings.error_folder, f, DUMP_Utils::SIGNATURE);
                }
            }
            break;
        case DUMP_Utils::SELF_SIGNATURE:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_self_signature_stmt.first + f + insert_self_signature_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_self_signature_stmt FAILED, the signature not have the results of the unpacking in the database! - %s",
                                      e.what());
                    DUMP_Utils::put_in_error(settings.error_folder, f, DUMP_Utils::SELF_SIGNATURE);
                }
            }
            break;
        case DUMP_Utils::USERID:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_userID_stmt.first + f + insert_userID_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_userID_stmt FAILED, the UserID not have the results of the unpacking in the database! - %s",
                                      e.what());
                    DUMP_Utils::put_in_error(settings.error_folder, f, DUMP_Utils::USERID);
                }
            }
            break;
        case DUMP_Utils::USER_ATTRIBUTES:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_userAtt_stmt.first + f + insert_userAtt_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_userID_stmt FAILED, the UserID not have the results of the unpacking in the database! - %s",
                                      e.what());
                    DUMP_Utils::put_in_error(settings.error_folder, f, DUMP_Utils::USER_ATTRIBUTES);
                }
            }
            break;
        case DUMP_Utils::CERTIFICATE:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_certificate_stmt.first + f + insert_certificate_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_certificate_stmt FAILED, the key will not have the certificate in the database! - %s",
                                      e.what());
                    DUMP_Utils::put_in_error(settings.error_folder, f, DUMP_Utils::CERTIFICATE);
                }
            }
            break;
        case DUMP_Utils::UNPACKER_ERRORS:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_unpackerErrors_stmt.first + f + insert_unpackerErrors_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_unpackerErrors_stmt FAILED, the error of the unpacking will not be in the database! - %s",
                                      e.what());
                    DUMP_Utils::put_in_error(settings.error_folder, f, DUMP_Utils::UNPACKER_ERRORS);
                }
            }
            break;
        case DUMP_Utils::BROKEN_KEY:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_brokenKey_stmt.first + f + insert_brokenKey_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_brokenKey_stmt FAILED, the broken key will not be in the database! - %s",
                                      e.what());
                    DUMP_Utils::put_in_error(settings.error_folder, f, DUMP_Utils::BROKEN_KEY);
                }
            }
            break;
        default:
            throw runtime_error("Table not recognized");
    }

}

void DUMPIMPORT_DBManager::UpdateSignatureIssuingFingerprint() {
    try{
        shared_ptr<Statement>(con->createStatement())->execute("COMMIT");
        shared_ptr<Statement>(con->createStatement())->execute("UPDATE Signatures INNER JOIN Signature_no_issuing_fp "
             "as ifp SET Signatures.issuingFingerprint = ifp.fp WHERE ifp.id = Signatures.id;");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void DUMPIMPORT_DBManager::UpdateSignatureIssuingUsername() {
    try{
        shared_ptr<Statement>(con->createStatement())->execute("COMMIT");
        shared_ptr<Statement>(con->createStatement())->execute("UPDATE Signatures INNER JOIN key_primary_userID on "
             "issuingFingerprint = fingerprint SET issuingUsername = name WHERE issuingUsername IS NULL;");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void DUMPIMPORT_DBManager::UpdateIsExpired() {
    try{
        shared_ptr<Statement>(con->createStatement())->execute("COMMIT");
        shared_ptr<Statement>(con->createStatement())->execute("UPDATE Signatures SET isExpired = 1 WHERE expirationTime < NOW();");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void DUMPIMPORT_DBManager::UpdateIsRevoked() {
    try{
        shared_ptr<Statement>(con->createStatement())->execute("COMMIT");
        shared_ptr<Statement>(con->createStatement())->execute("INSERT IGNORE INTO revocationSignatures select issuingKeyId, "
             "signedFingerprint, signedUsername FROM Signatures WHERE isRevocation = 1;");
        shared_ptr<Statement>(con->createStatement())->execute("UPDATE Signatures set isRevoked = 1 where isRevoked = 0 "
             "and isRevocation = 0 and (issuingKeyId, signedFingerprint, signedUsername) in (select * from revocationSignatures);");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void DUMPIMPORT_DBManager::UpdateIsValid() {
    try{
        shared_ptr<Statement>(con->createStatement())->execute("COMMIT");
        shared_ptr<Statement>(con->createStatement())->execute("UPDATE Signatures as s1 SET s1.isValid = -1 WHERE s1.isExpired = 1 "
             "or isRevoked = 1;");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void DUMPIMPORT_DBManager::lockTables(){
    try{
        shared_ptr<Statement>(con->createStatement())->execute("LOCK TABLES broken_keys WRITE, gpg_keyserver WRITE, "
             "KeyStatus WRITE, Pubkey WRITE, selfSignaturesMetadata WRITE, Signatures WRITE, SignatureStatus WRITE, revocationSignatures WRITE, "
             "Unpacker_errors WRITE, UserID WRITE, Signature_no_issuing_fp WRITE, UserAttribute WRITE, key_primary_userID WRITE;");
    }catch (exception &e){
        syslog(LOG_WARNING, "lock_tables_stmt FAILED, the query will be slowly! - %s",
                             e.what());
    }
}

void DUMPIMPORT_DBManager::unlockTables(){
    try{
        shared_ptr<Statement>(con->createStatement())->execute(("UNLOCK TABLES;"));
    }catch (exception &e){
        syslog(LOG_CRIT, "unlock_tables_stmt FAILED, the tables will remain locked! - %s",
                          e.what());
    }
}

void DUMPIMPORT_DBManager::openCSVFiles() {
    // Open files
    std::map<unsigned int, std::ofstream> file_list;
    for (const auto &it: DUMP_Utils::FILENAME){
        DUMPIMPORT_DBManager::file_list.insert(std::pair<unsigned int, ofstream>(
                it.first,
                ofstream(DUMP_Utils::get_file_name(settings.csv_folder, it.first, this_thread::get_id()), ios_base::app)));
    }
}
