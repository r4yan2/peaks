#include <sys/syslog.h>
#include <cstring>
#include <sstream>
#include <Misc/mpi.h>
#include <thread>

#include "DBManager.h"


using namespace sql;
using namespace std;

DUMP_DBManager::DUMP_DBManager(const Dump_DBConfig &un_settings){
    settings = un_settings;
};

DUMP_DBManager::DUMP_DBManager(const std::shared_ptr<DUMP_DBManager> & dbm){
    settings = dbm->get_settings();
    con = NULL;
    ensure_database_connection();
    get_dump_path_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT @@secure_file_priv as path;"));
    result = shared_ptr<ResultSet>(get_dump_path_stmt->executeQuery());
    result->next();
    dump_path = result->getString("path");
}

std::string DUMP_DBManager::get_dump_path(){
    get_dump_path_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT @@secure_file_priv as path;"));
    result = shared_ptr<ResultSet>(get_dump_path_stmt->executeQuery());
    result->next();
    dump_path = result->getString("path");
    return dump_path;
}

Dump_DBConfig DUMP_DBManager::get_settings(){
    return settings;
}

void DUMP_DBManager::ensure_database_connection(){
    bool connected = con != NULL && con->isValid(); //(con->isValid() || con->reconnect());
    if (connected)
        return;

    DUMP_DBManager::driver = get_driver_instance();
    DUMP_DBManager::con = shared_ptr<Connection>(driver->connect(settings.db_host, settings.db_user, settings.db_password));
    // Connect to the MySQL keys database
    con->setSchema(settings.db_database);
    
}

std::pair<std::string, std::string> DUMP_DBManager::dump_gpgkeyserver_stmt = make_pair<std::string, std::string>("SELECT version, ID, hex(fingerprint), hex(certificate), hash, is_unpacked, is_synchronized, error_code FROM gpg_keyserver INTO OUTFILE '", "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n';");

std::pair<std::string, std::string> DUMP_DBManager::dump_pubkey_stmt = make_pair<string, string>("SELECT keyId,version,hex(fingerprint),hex(priFingerprint),pubAlgorithm,creationTime,expirationTime, hex(e), hex(n),hex(p),hex(q),hex(g),hex(y),curveOID FROM Pubkey INTO OUTFILE '",
                                     "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n';");

std::pair<std::string, std::string> DUMP_DBManager::dump_signature_stmt = make_pair<string, string>("SELECT type, pubAlgorithm, hashAlgorithm, version, issuingKeyId, signedKeyId, hex(issuingFingerprint), hex(signedFingerprint), TO_BASE64(signedUsername), TO_BASE64(issuingUsername), sign_Uatt_id, regex, creationTime, hex(hashHeader), hex(signedHash), hashMismatch, keyExpirationTime, revocationCode, revocationReason, revocationSigId, isRevocable FROM Signatures INTO OUTFILE '",
                                     "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n';");

std::pair<std::string, std::string> DUMP_DBManager::dump_userID_stmt = make_pair<string, string>("SELECT ownerkeyID, hex(fingerprint), TO_BASE64(name) FROM UserID INTO OUTFILE '",
                                     "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n';");

std::pair<std::string, std::string> DUMP_DBManager::dump_self_signature_stmt = make_pair<string, string>("SELECT type, pubAlgorithm, hashAlgorithm, version, issuingKeyId, hex(issuingFingerprint), hex(preferedHash), hex(preferedCompression), hex(preferedSymmetric), trustLevel, keyExpirationTime, isPrimaryUserId, TO_BASE64(signedUserId) FROM selfSignaturesMetadata INTO OUTFILE '",
                                     "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n';");

std::pair<std::string, std::string> DUMP_DBManager::dump_userAtt_stmt = make_pair<string, string>("SELECT id, hex(fingerprint), TO_BASE64(name), encoding, hex(image) FROM UserAttribute INTO OUTFILE '",
                                     "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES STARTING BY '.' TERMINATED BY '\\n';");

std::pair<std::string, std::string> DUMP_DBManager::dump_unpackerErrors_stmt = make_pair<string, string>("SELECT version, hex(fingerprint), error FROM Unpacker_errors INTO OUTFILE '",
                                     "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
                                     "LINES STARTING BY '.' TERMINATED BY '\\n';");

std::pair<std::string, std::string> DUMP_DBManager::dump_brokenKey_stmt = make_pair<string, string>("SELECT id, hex(certificate), log FROM broken_keys INTO OUTFILE '",
                                     "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
                                     "LINES STARTING BY '.' TERMINATED BY '\\n';");

DUMP_DBManager::~DUMP_DBManager(){
};

void DUMP_DBManager::dumpCSV(const unsigned int &table){
    shared_ptr<Statement> query(con->createStatement());
    std::string statement;
    switch (table){
        case Utils::PUBKEY:
            statement = dump_pubkey_stmt.first + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_pubkey_stmt.second;
            break;
        case Utils::SIGNATURE:
            statement = dump_signature_stmt.first + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_signature_stmt.second;
            break;
        case Utils::SELF_SIGNATURE:
            statement = dump_self_signature_stmt.first + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_self_signature_stmt.second;
            break;
        case Utils::USERID:
            statement = dump_userID_stmt.first + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_userID_stmt.second;
            break;
        case Utils::USER_ATTRIBUTES:
            statement = dump_userAtt_stmt.first + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_userAtt_stmt.second;
            break;
        case Utils::CERTIFICATE:
            statement = dump_gpgkeyserver_stmt.first + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_gpgkeyserver_stmt.second;
            break;
        case Utils::UNPACKER_ERRORS:
            statement = dump_unpackerErrors_stmt.first + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_unpackerErrors_stmt.second;
            break;
        case Utils::BROKEN_KEY:
            statement = dump_brokenKey_stmt.first + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_brokenKey_stmt.second;
            break;
    }

    try{
        query->execute(statement);
    }catch(exception &e){
        switch (table){
            case Utils::PUBKEY:
                    syslog(LOG_CRIT, "dump_pubkey_stmt FAILED, the key will not be exported! - %s",
                                      e.what());
                    break;
            case Utils::SIGNATURE:
                    syslog(LOG_CRIT, "dump_signature_stmt FAILED, the signature will not be exported! - %s",
                                      e.what());
                    break;
            case Utils::SELF_SIGNATURE:
                    syslog(LOG_CRIT, "dump_self_signature_stmt FAILED, the signature will not be exported! - %s",
                                      e.what());
                    break;
            case Utils::USERID:
                    syslog(LOG_CRIT, "dump_userID_stmt FAILED, the UserID will not be exported! - %s",
                                      e.what());
                    break;
            case Utils::USER_ATTRIBUTES:
                    syslog(LOG_CRIT, "dump_userAtt_stmt FAILED, the User attribute data will not be exported! - %s",
                                      e.what());
                    break;
            case Utils::CERTIFICATE:
                    syslog(LOG_CRIT, "dump_gpgkeyserver_stmt FAILED, the certificates data will not be exported! - %s",
                                      e.what());
                    break;
            case Utils::UNPACKER_ERRORS:
                    syslog(LOG_CRIT, "dump_unpackerErrors_stmt FAILED, the error of the unpacking will not be exported! - %s",
                                      e.what());
                    break;
            case Utils::BROKEN_KEY:
                    syslog(LOG_CRIT, "dump_brokenKey_stmt FAILED, the certificate utterly broken will not be exported (maybe it's not that bad)! - %s",
                                      e.what());
                    break;
        }
    }
}

