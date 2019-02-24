#include <sys/syslog.h>
#include <cstring>
#include <sstream>
#include <Misc/mpi.h>
#include <thread>

#include "DBManager.h"


using namespace sql;
using namespace std;

// Database connector initialization
UNPACKER_DBManager::UNPACKER_DBManager(const Unpacker_DBConfig &un_settings){
    settings = un_settings;
};

void UNPACKER_DBManager::init_database_connection(){
    UNPACKER_DBManager::driver = get_driver_instance();
    UNPACKER_DBManager::con = shared_ptr<Connection>(driver->connect(settings.db_host, settings.db_user, settings.db_password));
    // Connect to the MySQL keys database
    con->setSchema(settings.db_database);

    //con->createStatement()->execute("set sql_log_bin = 0;");
    con->createStatement()->execute("set foreign_key_checks = 0;");

    // Create prepared Statements
    get_analyzable_cert_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT version, fingerprint, certificate "
                                         "FROM gpg_keyserver WHERE is_unpacked = 0 LIMIT ?"));
    
    get_signature_by_index = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT id "
                                         "FROM Signatures WHERE r = (?) and s = (?)"));
    
    insert_error_comments = shared_ptr<PreparedStatement>(con->prepareStatement("INSERT INTO Unpacker_errors "
                                         "(version, fingerprint, error) VALUES (?, ?, ?);"));
    
    set_key_not_analyzable = shared_ptr<PreparedStatement>(con->prepareStatement("UPDATE gpg_keyserver "
                                         "SET is_unpacked = -1 WHERE version = (?) and fingerprint = unhex(?)"));

    set_unpacking_status_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("UPDATE gpg_keyserver SET is_unpacked = 3 WHERE version = (?) and fingerprint = (?)"));
    
    insert_issuing_fingerprint = shared_ptr<PreparedStatement>(con->prepareStatement("UPDATE Signatures INNER JOIN "
                                         "(SELECT * FROM Signature_no_issuing_fp LIMIT ?) as ifp SET Signatures.issuingFingerprint = ifp.fp "
                                         "WHERE ifp.id = Signatures.id;"));
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
                                     "keyExpirationTime = nullif(@vkeyExpirationTime, ''), flags = UNHEX(@hexflags);");

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

UNPACKER_DBManager::~UNPACKER_DBManager(){
    for (auto &it: file_list){
        it.second.close();
    }
};

vector<UNPACKER_DBStruct::gpg_keyserver_data> UNPACKER_DBManager::get_certificates(const unsigned long &l) {
    vector<UNPACKER_DBStruct::gpg_keyserver_data> certificates;
    get_analyzable_cert_stmt->setString(1, to_string(l));
    result = shared_ptr<ResultSet>(get_analyzable_cert_stmt->executeQuery());
    while(result->next()){
        UNPACKER_DBStruct::gpg_keyserver_data tmp_field = {
                .version = result->getInt("version"),
                .fingerprint = result->getString("fingerprint"),
                .certificate = result->getString("certificate")
        };
        certificates.push_back(tmp_field);
    }
    return certificates;
}

bool UNPACKER_DBManager::existSignature(const UNPACKER_DBStruct::signatures &s){
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

void UNPACKER_DBManager::set_as_not_analyzable(const int &version, const string &fingerprint, const string &comment) {
    try{
        insert_error_comments->setInt(1, version);
        insert_error_comments->setBigInt(2, fingerprint);
        insert_error_comments->setString(3, comment);
        insert_error_comments->executeQuery();
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
        set_key_not_analyzable->executeQuery();

    }catch (exception &e){
        syslog(LOG_CRIT, "set_key_not_analyzable FAILED, the key will result not UNPACKED in the database! - %s", e.what());
    }
}

void UNPACKER_DBManager::write_unpacked_csv(const OpenPGP::Key::Ptr &key, const UNPACKER_DBStruct::Unpacker_errors &mod){
    try{
        ostream &f = file_list.at(UNPACKER_Utils::UNPACKED);
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

void UNPACKER_DBManager::write_pubkey_csv(const UNPACKER_DBStruct::pubkey &pubkey) {
    try{
        ostream &f = file_list.at(UNPACKER_Utils::PUBKEY);
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

void UNPACKER_DBManager::write_userID_csv(const UNPACKER_DBStruct::userID &uid) {
    try{
        ostream &f = file_list.at(UNPACKER_Utils::USERID);
        f << '.' << '"' << uid.ownerkeyID << "\",";
        f << '"' << hexlify(uid.fingerprint) << "\",";
        f << '"' << uid.name << "\",";
        f << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userID_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}


void UNPACKER_DBManager::write_userAttributes_csv(const UNPACKER_DBStruct::userAtt &ua) {
    try{
        ostream &f = file_list.at(UNPACKER_Utils::USER_ATTRIBUTES);
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

void UNPACKER_DBManager::write_signature_csv(const UNPACKER_DBStruct::signatures &ss) {
    try{
        ostream &f = file_list.at(UNPACKER_Utils::SIGNATURE);
        f << '.' << '"' << ss.type << "\",";
        f << '"' << ss.pubAlgorithm << "\",";
        f << '"' << ss.hashAlgorithm << "\",";
        f << '"' << ss.version << "\",";
        f << '"' << ss.issuingKeyId << "\",";
        f << '"' << ss.signedKeyId << "\",";
        f << '"' << hexlify(ss.issuingFingerprint) << "\",";
        f << '"' << hexlify(ss.signedFingerprint) << "\",";
        f << '"' << ss.signedUsername << "\",";
        f << '"' << ss.issuingUID << "\",";
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
        syslog(LOG_CRIT, "write_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::write_self_signature_csv(const UNPACKER_DBStruct::signatures &ss) {
    try{
        ostream &f = file_list.at(UNPACKER_Utils::SELF_SIGNATURE);
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

void UNPACKER_DBManager::write_unpackerErrors_csv(const UNPACKER_DBStruct::Unpacker_errors &mod){
    try{
        ostream &f = file_list.at(UNPACKER_Utils::UNPACKER_ERRORS);
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

void UNPACKER_DBManager::insertCSV(const vector<string> &files, const unsigned int &table){
    switch (table){
        case UNPACKER_Utils::PUBKEY:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_pubkey_stmt.first + f + insert_pubkey_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_pubkey_stmt FAILED, the key not have the results of the unpacking in the database! - %s",
                                      e.what());
                    UNPACKER_Utils::put_in_error(settings.unpacker_error_folder, f, UNPACKER_Utils::PUBKEY);
                }
            }
            break;
        case UNPACKER_Utils::SIGNATURE:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_signature_stmt.first + f + insert_signature_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_signature_stmt FAILED, the signature not have the results of the unpacking in the database! - %s",
                                      e.what());
                    UNPACKER_Utils::put_in_error(settings.unpacker_error_folder, f, UNPACKER_Utils::SIGNATURE);
                }
            }
            break;
        case UNPACKER_Utils::SELF_SIGNATURE:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_self_signature_stmt.first + f + insert_self_signature_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_self_signature_stmt FAILED, the signature not have the results of the unpacking in the database! - %s",
                                      e.what());
                    UNPACKER_Utils::put_in_error(settings.unpacker_error_folder, f, UNPACKER_Utils::SELF_SIGNATURE);
                }
            }
            break;
        case UNPACKER_Utils::USERID:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_userID_stmt.first + f + insert_userID_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_userID_stmt FAILED, the UserID not have the results of the unpacking in the database! - %s",
                                      e.what());
                    UNPACKER_Utils::put_in_error(settings.unpacker_error_folder, f, UNPACKER_Utils::USERID);
                }
            }
            break;
        case UNPACKER_Utils::USER_ATTRIBUTES:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_userAtt_stmt.first + f + insert_userAtt_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_userAtt_stmt FAILED, the UserID not have the results of the unpacking in the database! - %s",
                                      e.what());
                    UNPACKER_Utils::put_in_error(settings.unpacker_error_folder, f, UNPACKER_Utils::USER_ATTRIBUTES);
                }
            }
            break;
        case UNPACKER_Utils::UNPACKED:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute("CREATE TEMPORARY TABLE tmp_unpacker (version tinyint, fingerprint binary(20), unpacked tinyint);");
                    shared_ptr<Statement>(con->createStatement())->execute(insert_unpacked_stmt.first + f + insert_unpacked_stmt.second);
                    shared_ptr<Statement>(con->createStatement())->execute("UPDATE gpg_keyserver INNER JOIN tmp_unpacker ON tmp_unpacker.version = gpg_keyserver.version AND "
                                                            "tmp_unpacker.fingerprint = gpg_keyserver.fingerprint SET gpg_keyserver.is_unpacked = tmp_unpacker.unpacked;");
                    shared_ptr<Statement>(con->createStatement())->execute("DROP TEMPORARY TABLE tmp_unpacker;");
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_unpacked_stmt FAILED, the key will result NOT UNPACKED in the database! - %s",
                                      e.what());
                    UNPACKER_Utils::put_in_error(settings.unpacker_error_folder, f, UNPACKER_Utils::UNPACKED);
                }
            }
            break;
        case UNPACKER_Utils::UNPACKER_ERRORS:
            for (const auto &f: files){
                try{
                    shared_ptr<Statement>(con->createStatement())->execute(insert_unpackerErrors_stmt.first + f + insert_unpackerErrors_stmt.second);
                }catch (exception &e){
                    syslog(LOG_CRIT, "insert_unpackerErrors_stmt FAILED, the error of the unpacking will not be in the database! - %s",
                                      e.what());
                    UNPACKER_Utils::put_in_error(settings.unpacker_error_folder, f, UNPACKER_Utils::UNPACKER_ERRORS);
                }
            }
            break;
        default:
            throw runtime_error("Table not recognized");
    }

    // Delete inserted file
    for (const auto &f: files){
        try{
            remove(f.c_str());
        }catch (exception &e){
            syslog(LOG_CRIT, "File deleting FAILED, the following file MUST be deleted manually: %s. Error: %s", f.c_str(), e.what());
        }
    }
}

void UNPACKER_DBManager::UpdateSignatureIssuingFingerprint(const unsigned long &l) {
    try{
        shared_ptr<Statement>(con->createStatement())->execute("COMMIT");
        insert_issuing_fingerprint->setUInt64(1, l);
        insert_issuing_fingerprint->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::UpdateSignatureIssuingUsername() {
    try{
        shared_ptr<Statement>(con->createStatement())->execute("COMMIT");
        shared_ptr<Statement>(con->createStatement())->execute("UPDATE Signatures INNER JOIN key_primary_userID on "
              "issuingFingerprint = fingerprint SET issuingUsername = name WHERE issuingUsername IS NULL;");
        /*shared_ptr<Statement>(con->createStatement())->execute("UPDATE Signatures INNER JOIN Pubkey on "
              "Signatures.issuingFingerprint = Pubkey.fingerprint INNER JOIN key_primary_userID on "
              "Pubkey.PriFingerprint = key_primary_userID.fingerprint SET issuingUsername = name WHERE issuingUsername = \"\";");*/
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::UpdateIsExpired() {
    try{
        shared_ptr<Statement>(con->createStatement())->execute("COMMIT");
        shared_ptr<Statement>(con->createStatement())->execute("UPDATE Signatures SET isExpired = 1 WHERE expirationTime < NOW();");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::UpdateIsRevoked() {
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


void UNPACKER_DBManager::UpdateIsValid() {
    try{
        shared_ptr<Statement>(con->createStatement())->execute("COMMIT");
        shared_ptr<Statement>(con->createStatement())->execute("UPDATE Signatures as s1 SET s1.isValid = -1 WHERE s1.isExpired = 1 "
                                                                       "or isRevoked = 1;");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

void UNPACKER_DBManager::openCSVFiles(){
    // Open files
    for (const auto &it: UNPACKER_Utils::FILENAME){
        UNPACKER_DBManager::file_list.insert(std::pair<unsigned int, ofstream>(
                it.first,
                ofstream(UNPACKER_Utils::get_file_name(settings.unpacker_tmp_folder, it.first, this_thread::get_id()), ios_base::app)));
    }
}
