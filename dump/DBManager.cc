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

query_template DUMP_DBManager::dump_gpgkeyserver_stmt = {
    "SELECT version, ID, hex(fingerprint) as hexfingerprint, hex(certificate) as hexcertificate, hash, is_unpacked, is_synchronized, error_code FROM gpg_keyserver",
    " INTO OUTFILE '",
    "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES STARTING BY '.' TERMINATED BY '\\n';"
};

query_template DUMP_DBManager::dump_pubkey_stmt = {
    "SELECT keyId,version,hex(fingerprint) as hexfingerprint,hex(PriFingerprint) as hexpriFingerprint,pubAlgorithm,creationTime,expirationTime, revocationTime, hex(e) as hexe, hex(n) as hexn,hex(p) as hexp,hex(q) as hexq,hex(g) as hexg,hex(y) as hexy,curveOID, is_analyzed FROM Pubkey", 
    " INTO OUTFILE '",
    "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES STARTING BY '.' TERMINATED BY '\\n';"
};

query_template DUMP_DBManager::dump_signature_stmt = {
    "SELECT type, pubAlgorithm, hashAlgorithm, version, issuingKeyId, signedKeyId, hex(issuingFingerprint) as hexissuingFingerprint, hex(signedFingerprint) hexsignedFingerprint, TO_BASE64(signedUsername) as base64signedUsername, sign_Uatt_id, TO_BASE64(issuingUsername) as base64issuingUsername, regex, creationTime, expirationTime, hex(r) as hexr, hex(s) as hexs, hex(flags) as hexflags, hex(hashHeader) as hexhashHeader, hex(signedHash) as hexsignedHash, hashMismatch, keyExpirationTime, revocationCode, revocationReason, revocationSigId, isRevocable, isExportable, isExpired, isValid, isRevoked, isRevocation, is_analyzed FROM Signatures", 
    " INTO OUTFILE '",
    "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES STARTING BY '.' TERMINATED BY '\\n';"
};

query_template DUMP_DBManager::dump_userID_stmt = {
    "SELECT ownerkeyID, hex(fingerprint) as hexfingerprint, TO_BASE64(name) as base64name, is_analyze, bindingAuthentic FROM UserID",
    " INTO OUTFILE '",
    "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES STARTING BY '.' TERMINATED BY '\\n';"
};

query_template DUMP_DBManager::dump_self_signature_stmt = {
    "SELECT type, pubAlgorithm, hashAlgorithm, version, issuingKeyId, hex(issuingFingerprint) as hexissuingFingerprint, hex(preferedHash) as hexpreferedHash, hex(preferedCompression) as hexpreferedCompression, hex(preferedSymmetric) as hexpreferedSymmetric, trustLevel, keyExpirationTime, isPrimaryUserId, TO_BASE64(signedUserId) as base64signedUserId, userRole FROM selfSignaturesMetadata",
    " INTO OUTFILE '",
    "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES STARTING BY '.' TERMINATED BY '\\n';"
};

query_template DUMP_DBManager::dump_userAtt_stmt = {
    "SELECT id, hex(fingerprint) as hexfingerprint, TO_BASE64(name) as base64name, encoding, hex(image) as heximage FROM UserAttribute",
    " INTO OUTFILE '",
    "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES STARTING BY '.' TERMINATED BY '\\n';"
};

query_template DUMP_DBManager::dump_unpackerErrors_stmt = {
    "SELECT version, hex(fingerprint), error FROM Unpacker_errors",
    " INTO OUTFILE '",
    "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES STARTING BY '.' TERMINATED BY '\\n';"
};

query_template DUMP_DBManager::dump_brokenKey_stmt = {
    "SELECT id, hex(certificate), log FROM broken_keys",
    " INTO OUTFILE '",
    "' FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES STARTING BY '.' TERMINATED BY '\\n';"
};

DUMP_DBManager::~DUMP_DBManager(){
};

void DUMP_DBManager::write_gpg_keyserver_csv(){
    try{
        result = shared_ptr<ResultSet>(con->createStatement()->executeQuery(dump_gpgkeyserver_stmt[0]));
        ofstream f = ofstream(settings.output_folder + "DUMP" + Utils::FILENAME.at(Utils::CERTIFICATE), ios_base::app);
        while(result->next()){
            f << '.';
            f << '"' << result->getString("version") << "\",";
            f << '"' << result->getString("ID") << "\",";
            f << '"' << result->getString("hexfingerprint") << "\",";
            f << '"' << result->getString("hexcertificate") << "\",";
            f << '"' << result->getString("hash") << "\",";
            f << '"' << result->getString("is_unpacked") << "\",";
            f << '"' << result->getString("error_code") << "\",";
            f << "\n";
        }
    }catch (exception &e){
        syslog(LOG_CRIT, "dump_gpg_keyserver_csv FAILED, the key will not have the certificate in the database! - %s", e.what());
    }
}

void DUMP_DBManager::write_pubkey_csv() {
    try{
        result = shared_ptr<ResultSet>(con->createStatement()->executeQuery(dump_pubkey_stmt[0]));
        ofstream f = ofstream(settings.output_folder + "DUMP" + Utils::FILENAME.at(Utils::PUBKEY), ios_base::app);
        while(result->next()){
            f << '.';
            f << '"' << result->getString("keyId") << "\",";
            f << '"' << result->getString("version") << "\",";
            f << '"' << result->getString("hexfingerprint") << "\",";
            f << '"' << result->getString("hexpriFingerprint") << "\",";
            f << '"' << result->getString("pubAlgorithm") << "\",";
            f << '"' << result->getString("creationTime") << "\",";
            f << '"' << result->getString("expirationTime") << "\",";
            f << '"' << result->getString("hexe") << "\",";
            f << '"' << result->getString("hexn") << "\",";
            f << '"' << result->getString("hexp") << "\",";
            f << '"' << result->getString("hexq") << "\",";
            f << '"' << result->getString("hexg") << "\",";
            f << '"' << result->getString("hexy") << "\",";
            f << '"' << result->getString("curveOID") << "\",";
            f << "\n";
        }
    }catch (exception &e){
        syslog(LOG_CRIT, "write_pubkey_csv FAILED, the key not have the results of the unpacking in the database! - %s", e.what());
    }
}

void DUMP_DBManager::write_signature_csv() {
    try{
        result = shared_ptr<ResultSet>(con->createStatement()->executeQuery(dump_signature_stmt[0]));
        ofstream f = ofstream(settings.output_folder + "DUMP" + Utils::FILENAME.at(Utils::SIGNATURE), ios_base::app);
        while(result->next()){
            f << '.';
            f << '"' << result->getString("type") << "\",";
            f << '"' << result->getString("pubAlgorithm") << "\",";
            f << '"' << result->getString("hashAlgorithm") << "\",";
            f << '"' << result->getString("version") << "\",";
            f << '"' << result->getString("issuingKeyId") << "\",";
            f << '"' << result->getString("signedKeyId") << "\",";
            f << '"' << result->getString("hexissuingFingerprint") << "\",";
            f << '"' << result->getString("hexsignedFingerprint") << "\",";
            f << '"' << result->getString("base64signedUsername") << "\",";
            f << '"' << result->getString("base64issuingUsername") << "\",";
            f << '"' << result->getString("sign_uatt_id") << "\",";
            f << '"' << result->getString("regex") << "\",";
            f << '"' << result->getString("creationTime") << "\",";
            f << '"' << result->getString("expirationTime") << "\",";
            f << '"' << result->getString("hexr") << "\",";
            f << '"' << result->getString("hexs") << "\",";
            f << '"' << result->getString("hexflags") << "\",";
            f << '"' << result->getString("hexhashHeader") << "\",";
            f << '"' << result->getString("hexsignedHash") << "\",";
            f << '"' << result->getString("hashMismatch") << "\",";
            f << '"' << result->getString("keyExpirationTime") << "\",";
            f << '"' << result->getString("revocationCode") << "\",";
            f << '"' << result->getString("revocationReason") << "\",";
            f << '"' << result->getString("revocationSigId") << "\",";
            f << '"' << result->getString("isRevocable") << "\",";
            f << '"' << result->getString("isExportable") << "\",";
            f << '"' << result->getString("isExpired") << "\",";
            f << '"' << result->getString("isRevocation") << "\",";
            f << "\n";
        }
    }catch (exception &e){
        syslog(LOG_CRIT, "write_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s", e.what());
    }
}

void DUMP_DBManager::write_userID_csv() {
    try{
        result = shared_ptr<ResultSet>(con->createStatement()->executeQuery(dump_userID_stmt[0]));
        ofstream f = ofstream(settings.output_folder + "DUMP" + Utils::FILENAME.at(Utils::USERID), ios_base::app);
        while(result->next()){
            f << '.';
            f << '"' << result->getString("ownerkeyID") << "\",";
            f << '"' << result->getString("hexfingerprint") << "\",";
            f << '"' << result->getString("base64name") << "\",";
            f << "\n";
        }
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userID_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}

void DUMP_DBManager::write_userAttributes_csv() {
    try{
        result = shared_ptr<ResultSet>(con->createStatement()->executeQuery(dump_userAtt_stmt[0]));
        ofstream f = ofstream(settings.output_folder + "DUMP" + Utils::FILENAME.at(Utils::USER_ATTRIBUTES), ios_base::app);
        while(result->next()){
            f << '.';
            f << '"' << result->getString("id") << "\",";
            f << '"' << result->getString("hexfingerprint") << "\",";
            f << '"' << result->getString("base64name") << "\",";
            f << '"' << result->getString("encoding") << "\",";
            f << '"' << result->getString("heximage") << "\",";
            f << "\n";
        }
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userAttributes_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}

void DUMP_DBManager::write_self_signature_csv() {
    try{
        result = shared_ptr<ResultSet>(con->createStatement()->executeQuery(dump_self_signature_stmt[0]));
        ofstream f = ofstream(settings.output_folder + "DUMP" + Utils::FILENAME.at(Utils::SELF_SIGNATURE), ios_base::app);
        while(result->next()){
            f << '.';
            f << '"' << result->getString("type") << "\",";
            f << '"' << result->getString("pubAlgorithm") << "\",";
            f << '"' << result->getString("hashAlgorithm") << "\",";
            f << '"' << result->getString("version") << "\",";
            f << '"' << result->getString("issuingKeyId") << "\",";
            f << '"' << result->getString("hexissuingFingerprint") << "\",";
            f << '"' << result->getString("hexpreferedHash") << "\",";
            f << '"' << result->getString("hexpreferedCompression") << "\",";
            f << '"' << result->getString("hexpreferedSymmetric") << "\",";
            f << '"' << result->getString("trustLevel") << "\",";
            f << '"' << result->getString("keyExpirationTime") << "\",";
            f << '"' << result->getString("isPrimaryUserId") << "\",";
            f << '"' << result->getString("base64signedUserId") << "\",";
            f << "\n";
        }
    }catch (exception &e){
        syslog(LOG_CRIT, "write_self_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s", e.what());
    }
}

void DUMP_DBManager::dumplocalCSV(const unsigned int &table){
    switch (table){
        case Utils::PUBKEY:
            write_pubkey_csv();
            break;
        case Utils::SIGNATURE:
            write_signature_csv();
            break;
        case Utils::SELF_SIGNATURE:
            write_self_signature_csv();
            break;
        case Utils::USERID:
            write_userID_csv();
            break;
        case Utils::USER_ATTRIBUTES:
            write_userAttributes_csv();
            break;
        case Utils::CERTIFICATE:
            write_gpg_keyserver_csv();
            break;
    }
}

void DUMP_DBManager::dumpCSV(const unsigned int &table){
    shared_ptr<Statement> query(con->createStatement());
    std::string statement;
    switch (table){
        case Utils::PUBKEY:
            statement = dump_pubkey_stmt[0] + dump_pubkey_stmt[1] + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_pubkey_stmt[2];
            break;
        case Utils::SIGNATURE:
            statement = dump_signature_stmt[0] + dump_signature_stmt[1] + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_signature_stmt[2];
            break;
        case Utils::SELF_SIGNATURE:
            statement = dump_self_signature_stmt[0] + dump_self_signature_stmt[1] + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_self_signature_stmt[2];
            break;
        case Utils::USERID:
            statement = dump_userID_stmt[0] + dump_userID_stmt[1] + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_userID_stmt[2];
            break;
        case Utils::USER_ATTRIBUTES:
            statement = dump_userAtt_stmt[0] + dump_userAtt_stmt[1] + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_userAtt_stmt[2];
            break;
        case Utils::CERTIFICATE:
            statement = dump_gpgkeyserver_stmt[0] + dump_gpgkeyserver_stmt[1] + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_gpgkeyserver_stmt[2];
            break;
        case Utils::UNPACKER_ERRORS:
            statement = dump_unpackerErrors_stmt[0] + dump_unpackerErrors_stmt[1] + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_unpackerErrors_stmt[2];
            break;
        case Utils::BROKEN_KEY:
            statement = dump_brokenKey_stmt[0] + dump_brokenKey_stmt[1] + dump_path + "DUMP" + Utils::FILENAME.at(table) + dump_brokenKey_stmt[2];
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

