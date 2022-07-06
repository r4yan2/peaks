#include "DBManager.h"
#include <cppconn/connection.h>
#include <sys/syslog.h>
#include <numeric>
#include <sstream>
#include "config.h"
#include <common/FileManager.h>
#include <common/Thread_Pool.h>
#include <tuple>
#include <recon_daemon/pTreeDB.h>

using namespace std;
namespace peaks{
namespace common{
DBManager::DBManager():
    tables(),
    driver(get_driver_instance())
{
    connection_properties["hostName"] = CONTEXT.dbsettings.db_host;
    connection_properties["userName"] = CONTEXT.dbsettings.db_user;
    connection_properties["password"] = CONTEXT.dbsettings.db_password;
    connection_properties["port"] = CONTEXT.dbsettings.db_port;
    connection_properties["CLIENT_MULTI_STATEMENTS"] = true;
    connection_properties["OPT_CHARSET_NAME"] = "utf8mb4";
    connection_properties["preInit"] = "SET NAMES utf8mb4;SET CHARACTER SET utf8mb4;";
    connection_properties["OPT_LOCAL_INFILE"] = 1;
    con = driver->connect(connection_properties);

    critical_section = false;
}

void DBManager::connect_schema(){
    con->setSchema(CONTEXT.dbsettings.db_database);
    get_certificate_from_filestore_stmt = prepare_query("SELECT filename, origin, len FROM gpg_keyserver WHERE hash = (?)");
    get_certificate_from_filestore_by_id_stmt = prepare_query("SELECT filename, origin, len, hash FROM gpg_keyserver WHERE keyId = (?)");
    get_filestore_index_from_stash_stmt = prepare_query("SELECT value FROM stash WHERE name = 'filestore_index'");
    store_filestore_index_to_stash_stmt = prepare_query("REPLACE INTO stash (name, value) VALUES ('filestore_index', ?)");
    get_from_cache_stmt = prepare_query("SELECT value, TIMESTAMPDIFF(SECOND, NOW(), created) as diff FROM stash WHERE name = (?)");
    set_in_cache_stmt = prepare_query("REPLACE INTO stash(`name`,`value`, `created`) VALUES (?, ?, NOW())");
    delete_key_from_gpgkeyserver_stmt = prepare_query("DELETE FROM gpg_keyserver where keyId = (?)");
    check_blocklist_stmt = prepare_query("SELECT 1 FROM blocklist WHERE keyId = (?)");
    fetch_blocklist_stmt = prepare_query("SELECT keyId FROM blocklist");
    insert_gpg_stmt = prepare_query("REPLACE INTO gpg_keyserver VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, NOW());");
    insert_into_blocklist_stmt = prepare_query("INSERT IGNORE INTO blocklist (keyId) VALUES (?)");
    insert_into_pubkey_stmt = prepare_query("INSERT INTO Pubkey(keyId,version,fingerprint,priFingerprint,pubAlgorithm,creationTime,expirationTime,e,n,p,q,g,y,curveOID) VALUES(?,?,?,?,?,?,nullif(?, ''),?,?,?,?,?,?,?)");
    insert_into_signature_stmt = prepare_query("INSERT INTO Signatures(type,pubAlgorithm,hashAlgorithm,version,issuingKeyId,signedKeyId,issuingFingerprint,signedFingerprint,signedUsername,issuingUsername,sign_Uatt_id,regex,creationTime,keyExpirationTime,r,s,flags,hashHeader,signedHash,hashMismatch,expirationTime,revocationCode,revocationReason,revocationSigId,isRevocable,isExportable,isExpired,isRevocation) VALUES(?,?,?,?,?,?,nullif(?, ''),?,nullif(?, ''),nullif(?, ''),nullif(?, ''),nullif(?, ''),?,nullif(?, ''),?,?,nullif(?, ''),?,?,?,nullif(?, ''),?,?,?,?,?,?,?)");
    insert_into_selfsignature_stmt = prepare_query("INSERT INTO selfSignaturesMetadata(type,pubAlgorithm,hashAlgorithm,version,issuingKeyId,issuingFingerprint,preferedHash,preferedCompression,preferedSymmetric,trustLevel,keyExpirationTime,isPrimaryUserId,signedUserId) VALUES(?,?,?,?,?,?,?,?,?,?,nullif(?, ''),?,?)");
    insert_into_userid_stmt = prepare_query("INSERT INTO UserID(ownerkeyID, fingerprint, name) VALUES(?,?,?)");
    insert_into_userattributes_stmt = prepare_query("INSERT INTO UserAttribute(id, fingerprint, name, encoding, image) VALUES(?,?,?,?,?)");
    insert_into_unpackererrors_stmt = prepare_query("INSERT INTO Unpacker_errors(version,fingerprint,error) VALUES(?,?,?)");
    update_gpg_keyserver_stmt = prepare_query("UPDATE gpg_keyserver SET is_unpacked = (?) WHERE version = (?) AND fingerprint = (?)");
    insert_error_comments = prepare_query("INSERT INTO Unpacker_errors "
                                         "(version, fingerprint, error) VALUES (?, ?, ?);");

    set_key_not_analyzable = prepare_query("UPDATE gpg_keyserver "
                                         "SET is_unpacked = -1 WHERE version = (?) and fingerprint = unhex(?)");

    // filestorage
    int idx = 0;
    try{
        unique_ptr<DBResult> result = get_filestore_index_from_stash_stmt->execute();
        while (result->next()){
            idx = atoi(result->getString("value").c_str());
        }
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    CONTEXT.filestorage_index = idx;
    string format = CONTEXT.dbsettings.filestorage_format;
    int sz = snprintf(nullptr, 0, format.c_str(), idx);
    vector<char> buf(sz + 1);
    snprintf(&buf[0], buf.size(), format.c_str(), idx);
    string tmp(buf.data(), buf.size());
    filestorage_handler = FILEMANAGER.openFile(tmp, true);
}

void DBManager::check_sql_mode(){
    shared_ptr<DBQuery> sqlmode_query = prepare_query("SELECT @@SESSION.sql_mode AS mode");
    unique_ptr<DBResult> result = sqlmode_query->execute();
    string mode;
    if (result->next()){
        mode = result->getString("mode");
    }
    else{
        syslog(LOG_WARNING, "Could not determine sql mode, refer to the README for further info");
        return;
    }
    if (mode.find("ONLY_FULL_GROUP_BY") != string::npos) {
        syslog(LOG_INFO, "Found sql mode ONLY_FULL_GROUP_BY active, attempting to change");
        execute_query("SET SESSION sql_mode=(SELECT REPLACE(@@SESSION.sql_mode,'ONLY_FULL_GROUP_BY',''))");
        unique_ptr<DBResult> result = sqlmode_query->execute();
        if (result->next()){
            mode = result->getString("mode");
            if (mode.find("ONLY_FULL_GROUP_BY") != string::npos) {
                syslog(LOG_WARNING, "Could not change sql mode, refer to the README for further info");
                exit(1);
            } else {
                syslog(LOG_INFO, "SQL mode changed");
            }
        }
    }
}

void DBManager::init_database(const string &filename){

    string dbinit = "CREATE DATABASE IF NOT EXISTS `" + CONTEXT.dbsettings.db_database + "`;";
    execute_query(dbinit);
    con->setSchema(CONTEXT.dbsettings.db_database);
    ifstream inFile;
    inFile.open(filename);
    if (inFile.fail())
    {
        cerr << "Could not find init file for DB" << std::endl;
    }
    stringstream buffer;
    buffer << inFile.rdbuf();
    execute_query(buffer.str());
    cerr << "Done init database" << std::endl;
}

DBManager::~DBManager(){
    con->close();
    delete con;
    if (driver != NULL)
        driver->threadEnd();

}

bool DBManager::ensure_database_connection(){
    bool connected = con != NULL && con->isValid();
    if (connected)
        return connected;

    driver = get_driver_instance();
    con = driver->connect(connection_properties);
    con->setSchema(CONTEXT.dbsettings.db_database);
    check_sql_mode();
    return connected;
}

void DBManager::begin_transaction(){
    if (critical_section) //already in transaction
        return;
    try{
        critical_section = true;
        //execute_query("SET AUTOCOMMIT = 0");
        //execute_query("SET UNIQUE_CHECKS = 0");
        execute_query("SET sql_log_bin = 0");
        execute_query("SET foreign_key_checks = 0");
        execute_query("START TRANSACTION");
    }catch (exception &e){
        syslog(LOG_WARNING, "begin transaction FAILED, data corruption may occur! - %s", e.what());
    }
}

void DBManager::end_transaction(){
    if (!critical_section)
        return; //already ended
    try{
        critical_section = false;
        execute_query("COMMIT");
        //execute_query("SET AUTOCOMMIT = 1");
        //execute_query("SET UNIQUE_CHECKS = 1");
        execute_query("SET sql_log_bin = 1");
        execute_query("SET foreign_key_checks = 1");
    }catch (exception &e){
        syslog(LOG_WARNING, "end transaction FAILED, data corruption may occur! - %s", e.what());
    }
}

void DBManager::rollback_transaction(){
    if (!critical_section)
        return; //already ended
    try{
        CONTEXT.critical_section = false;
        execute_query("ROLLBACK");
        //execute_query("SET AUTOCOMMIT = 1");
        //execute_query("SET UNIQUE_CHECKS = 1");
        execute_query("SET sql_log_bin = 1");
        execute_query("SET foreign_key_checks = 1");
    }catch (exception &e){
        syslog(LOG_WARNING, "end transaction FAILED, data corruption may occur! - %s", e.what());
    }
}

void DBManager::lockTables(){
    try{
        string s = accumulate(++tables.begin(), tables.end(), Utils::TABLENAME.at(tables[0]), [](string &a, unsigned int &b){return a + std::string(" WRITE, ") + Utils::TABLENAME.at(b);});
        string lockQuery = std::string("LOCK TABLES ") + s + std::string(" WRITE");
        
        execute_query(lockQuery);
    }catch (exception &e){
        syslog(LOG_WARNING, "lock_tables_stmt FAILED, the query will be slower! - %s", e.what());
    }
}

void DBManager::unlockTables(){
    try{
        execute_query(("UNLOCK TABLES;"));
    }catch (exception &e){
        syslog(LOG_CRIT, "unlock_tables_stmt FAILED, the tables will remain locked! - %s",
                          e.what());
    }
}

shared_ptr<DBQuery> DBManager::prepare_query(const std::string & stmt){
    shared_ptr<DBQuery> res = std::make_shared<DBQuery>(con, stmt);
    return res; 
}

void DBManager::execute_query(const string & stmt){
    syslog(LOG_DEBUG, "Execute query %s", stmt.c_str());
    unique_ptr<sql::Statement>(con->createStatement())->execute(stmt);
}

tuple<std::string, int> DBManager::store_certificate_to_filestore(const std::string &certificate){
    if (FILEMANAGER.querySize(filestorage_handler) + certificate.size() > CONTEXT.dbsettings.filestorage_maxsize * 1024 * 1024){
        // create new file
        int idx = CONTEXT.filestorage_index + 1;
        string format = CONTEXT.dbsettings.filestorage_format;
        int sz = snprintf(nullptr, 0, format.c_str(), idx);
        vector<char> buf(sz + 1);
        snprintf(&buf[0], buf.size(), format.c_str(), idx);
        string tmp(buf.data(), buf.size());
        filestorage_handler = FILEMANAGER.openFile(tmp, true);
    try{
        store_filestore_index_to_stash_stmt->setInt(1, idx);
        store_filestore_index_to_stash_stmt->execute();
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not update index value to DB: %s", e.what());
    }
        
    }
    size_t orig = FILEMANAGER.write(filestorage_handler, certificate);
    return make_tuple(FILEMANAGER.queryName(filestorage_handler), orig);
}

string DBManager::get_certificate_from_filestore(const std::string &filename, const int start, const int length){
    shared_ptr<std::istream> file = get_certificate_stream_from_filestore(filename, start);
    string buffer(length, ' ');
    file->read(&buffer[0], length); 
    return buffer;
}

void DBManager::remove_certificate_from_filestore(const std::string &filename, const int start, const int length){
    shared_ptr<std::fstream> file = std::make_shared<std::fstream>(filename);
    file->seekp(start, std::ios_base::beg);
    std::string s(length, '0');
    file->write(s.c_str(), s.size());
    file->close();
}

string DBManager::get_certificate_from_filestore(const std::string &hash){
    string filename;
    int start, length;
    try{
        get_certificate_from_filestore_stmt->setString(1, hash);
        unique_ptr<DBResult> result = get_certificate_from_filestore_stmt->execute();
        while(result->next()){
            filename = result->getString("filename");
            start = result->getInt("origin");
            length = result->getInt("len");
        }
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    if (filename == "")
        return "";
    return get_certificate_from_filestore(filename, start, length);
}

string DBManager::get_certificate_from_filestore_by_id(const std::string &kid){
    string filename;
    int start, length;
    try{
        get_certificate_from_filestore_by_id_stmt->setString(1, kid);
        unique_ptr<DBResult> result = get_certificate_from_filestore_by_id_stmt->execute();
        while(result->next()){
            filename = result->getString("filename");
            start = result->getInt("origin");
            length = result->getInt("len");
        }
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    if (filename == "")
        return "";
    return get_certificate_from_filestore(filename, start, length);
}

void DBManager::remove_key_from_db(const std::string &kid){
    try{
        begin_transaction();
        get_certificate_from_filestore_by_id_stmt->setBigInt(1, kid);
        std::unique_ptr<DBResult> result = get_certificate_from_filestore_by_id_stmt->execute();
        if (result->next()) {
            std::string filename = result->getString("filename");
            int origin = result->getInt("origin");
            int len = result->getInt("len");
            std::string hash = result->getString("hash");
            remove_certificate_from_filestore(filename, origin, len);
            delete_key_from_gpgkeyserver_stmt->setBigInt(1, kid);
            delete_key_from_gpgkeyserver_stmt->execute();
            PTREE.remove(hash);
        }
        end_transaction();
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not delete key: %s", e.what());
        rollback_transaction();
    }
}

bool DBManager::check_blocklist(const std::string &kid){
    try{
        check_blocklist_stmt->setBigInt(1, kid);
        std::unique_ptr<DBResult> result = check_blocklist_stmt->execute();
        return !result->next();
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not check blocklist: %s", e.what());
    }
    return false;
}

std::set<std::string> DBManager::fetch_blocklist(){
    std::set<std::string> res;
    try{
        std::unique_ptr<DBResult> result = fetch_blocklist_stmt->execute();
        while (result->next())
            res.insert(result->getString("keyId"));
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not check blocklist: %s", e.what());
    }
    return res;
}

void DBManager::insert_gpg_keyserver(const DBStruct::gpg_keyserver_data &gk) {
    check_database_connection();
    begin_transaction();
    std::tuple <std::string, int> res = store_certificate_to_filestore(gk.certificate); 
    try {
        insert_gpg_stmt->setInt(1, gk.version);
        insert_gpg_stmt->setBigInt(2, gk.ID);
        insert_gpg_stmt->setBlob(3, gk.fingerprint);
        insert_gpg_stmt->setString(4, gk.hash);
        insert_gpg_stmt->setInt(5, gk.error_code);
        insert_gpg_stmt->setString(6, std::get<0>(res));
        insert_gpg_stmt->setInt(7, std::get<1>(res));
        insert_gpg_stmt->setInt(8, gk.certificate.size());
        insert_gpg_stmt->execute();
        end_transaction();
    }catch (std::exception &e){
        syslog(LOG_ERR, "insert_gpg_stmt FAILED - %s", e.what());
        rollback_transaction();
    }
}

shared_ptr<std::istream> DBManager::get_certificate_stream_from_filestore(const std::string &filename, const int start){
    shared_ptr<std::istream> file = std::make_shared<std::ifstream>(filename, std::ios::in | std::ios::binary);
    file->seekg(start);
    return file;
  //auto init_buf = std::make_unique<substreambuf>(start, length);
  //return std::make_unique<std::istream>(
  //  init_buf->open(filename, std::ios_base::in | std::ios::binary)
  //);
    //std::shared_ptr<std::ifstream> file = std::make_shared<std::ifstream>(filename, std::ios::in | std::ios::binary);
    //std::shared_ptr<std::streambuf> filebuf = std::make_shared<std::streambuf>(file->rdbuf());
    //std::shared_ptr<substreambuf> subuf = std::make_shared<substreambuf>(filebuf, start, length);
    //std::shared_ptr<std::istream> res = std::make_shared<std::istream>(subuf);
    //return res;
}

int DBManager::get_from_cache(const string &key, std::string &value){
    string res = "";
    int diff = false;
    try{
        get_from_cache_stmt->setString(1, key);
        unique_ptr<DBResult> result = get_from_cache_stmt->execute();
        while (result->next()){
            value = result->getString("value");
            diff = result->getBoolean("diff");
        }
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    return diff;

}

void DBManager::store_in_cache(const string &key, const std::string &value){
    try{
        set_in_cache_stmt->setString(1, key);
        set_in_cache_stmt->setString(2, value);
        unique_ptr<DBResult> result = set_in_cache_stmt->execute();
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not save data in the DB: %s", e.what());
    }
}

void DBManager::openCSVFiles() {
    // Open files
    for (const auto &it: tables)
	    file_list[it] = FILEMANAGER.openFile(Utils::get_file_name(CONTEXT.dbsettings.tmp_folder, it));
}

void DBManager::flushCSVFiles(){
    for (auto &it: file_list){
        FILEMANAGER.flushFile(it.second);
    }
}

void DBManager::closeCSVFiles(){
    for (auto &it: file_list){
        FILEMANAGER.closeFile(it.second);
    }
}

void DBManager::insertCSV(bool lock){
    if (lock) lockTables();
    for (const auto &table: tables){
        string f = Utils::get_file_name(CONTEXT.dbsettings.tmp_folder, table);
        if (!Utils::check_file_exists(f))
            continue;
        begin_transaction();
        insertCSV(f, table);
        end_transaction();

        // Delete inserted file
        if (CONTEXT.get<bool>("noclean", false) == 0){
            try{
                remove(f.c_str());
            }catch (exception &e){
                syslog(LOG_CRIT, "Error during deletion of files. The file will remaining in the temp folder. - %s",
                                  e.what());
            }
        }

    }
    if (lock) unlockTables();
}

void DBManager::insertCSV(const string &f, const unsigned int &table){
    unsigned int backoff = 1;
    unsigned int num_retries = 0;
    string statement;
    syslog(LOG_INFO, "peaks DB: Working on %s", f.c_str());
    switch (table){
        case Utils::TABLES::PUBKEY:
            statement = insert_pubkey_stmt.first + f + insert_pubkey_stmt.second;
            break;
        case Utils::TABLES::SIGNATURE:
            statement = insert_signature_stmt.first + f + insert_signature_stmt.second;
            break;
        case Utils::TABLES::SELF_SIGNATURE:
            statement = insert_self_signature_stmt.first + f + insert_self_signature_stmt.second;
            break;
        case Utils::TABLES::USERID:
            statement = insert_userID_stmt.first + f + insert_userID_stmt.second;
            break;
        case Utils::TABLES::USER_ATTRIBUTES:
            statement = insert_userAtt_stmt.first + f + insert_userAtt_stmt.second;
            break;
        case Utils::TABLES::CERTIFICATE:
            statement = insert_certificate_stmt.first + f + insert_certificate_stmt.second;
            break;
        case Utils::UNPACKED:
            execute_query(create_unpacker_tmp_table);
            statement = insert_unpacked_stmt.first + f + insert_unpacked_stmt.second;
            break;
        case Utils::TABLES::UNPACKER_ERRORS:
            statement = insert_unpackerErrors_stmt.first + f + insert_unpackerErrors_stmt.second;
            break;
    }

    do{
        try{
            execute_query(statement);
            if (table == Utils::UNPACKED){
                execute_query(update_gpg_keyserver);
                execute_query(drop_unpacker_tmp_table);
            }
            backoff = 0;
        }catch(exception &e){
            num_retries += 1;
            unsigned int sleep_seconds = (backoff << num_retries) * 60 ;
            switch (table){
                case Utils::TABLES::PUBKEY:
                        syslog(LOG_CRIT, "insert_pubkey_stmt FAILED, the key not have the results of the unpacking in the database! - %s",
                                          e.what());
                        break;
                case Utils::TABLES::SIGNATURE:
                        syslog(LOG_CRIT, "insert_signature_stmt FAILED, the signature not have the results of the unpacking in the database! - %s",
                                          e.what());
                        break;
                case Utils::TABLES::SELF_SIGNATURE:
                        syslog(LOG_CRIT, "insert_self_signature_stmt FAILED, the signature not have the results of the unpacking in the database! - %s",
                                          e.what());
                        break;
                case Utils::TABLES::USERID:
                        syslog(LOG_CRIT, "insert_userID_stmt FAILED, the UserID not have the results of the unpacking in the database! - %s",
                                          e.what());
                        break;
                case Utils::TABLES::USER_ATTRIBUTES:
                        syslog(LOG_CRIT, "insert_userAtt_stmt FAILED, the UserID not have the results of the unpacking in the database! - %s",
                                          e.what());
                        break;
                case Utils::TABLES::CERTIFICATE:
                        syslog(LOG_CRIT, "insert_certificate_stmt FAILED, the key will not have the certificate in the database! - %s",
                                          e.what());
                        break;
                case Utils::UNPACKED:
                        syslog(LOG_CRIT, "insert_unpacked_stmt FAILED, the key will result NOT UNPACKED in the database! - %s",
                                          e.what());
                        execute_query(drop_unpacker_tmp_table);
                        break;
                case Utils::TABLES::UNPACKER_ERRORS:
                        syslog(LOG_CRIT, "insert_unpackerErrors_stmt FAILED, the error of the unpacking will not be in the database! - %s",
                                          e.what());
                        break;
            }
            this_thread::sleep_for(chrono::seconds{sleep_seconds});
        }
    } while (backoff > 0 && num_retries < 5);
    if (backoff > 0){
        Utils::put_in_error(CONTEXT.dbsettings.error_folder, f, table);
    }
}

void DBManager::insert_into_blocklist(const std::string &ID) {
    try{
        insert_into_blocklist_stmt->setBigInt(1, ID);
        insert_into_blocklist_stmt->execute();
    
    }catch(exception &e){
        syslog(LOG_CRIT, "insert_into_blocklist_stmt FAILED, the blocklist was not updated! - %s",
                          e.what());
    }
}

void DBManager::set_as_not_analyzable(const int &version, const string &fingerprint, const string &comment) {
    try{
        insert_error_comments->setInt(1, version);
        insert_error_comments->setBlob(2, fingerprint);
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



void DBManager::write_unpacked_csv(const OpenPGP::Key::Ptr &key, const DBStruct::Unpacker_errors &mod){
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
        FILEMANAGER.write(file_list.at(Utils::TABLES::UNPACKED), f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_unpacked_csv FAILED, the key will result not UNPACKED in the database! - %s", e.what());
    }
}


void DBManager::write_unpacked_table(const OpenPGP::Key::Ptr &key, const DBStruct::Unpacker_errors &mod){
    try {
        if (mod.modified){
            update_gpg_keyserver_stmt->setInt(1, 2);
        } else {
            update_gpg_keyserver_stmt->setInt(1, 1);
        }
        update_gpg_keyserver_stmt->setInt(2, key->version());
        update_gpg_keyserver_stmt->setString(3, key->fingerprint());
        update_gpg_keyserver_stmt->execute();
    } catch (exception &e){
        syslog(LOG_CRIT, "write_unpacked_table FAILED, the key will result not UNPACKED in the database! - %s", e.what());
    }
}

void DBManager::write_pubkey_csv(const DBStruct::pubkey &pubkey) {
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
        FILEMANAGER.write(file_list.at(Utils::TABLES::PUBKEY), f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_pubkey_csv FAILED, the key not have the results of the unpacking in the database! - %s", e.what());
    }
}

void DBManager::write_pubkey_table(const DBStruct::pubkey &pubkey) {
    try{
        int pos = 1;
        insert_into_pubkey_stmt->setString(pos++, pubkey.keyId);
        insert_into_pubkey_stmt->setInt(pos++, pubkey.version);
        insert_into_pubkey_stmt->setString(pos++, pubkey.fingerprint);
        insert_into_pubkey_stmt->setString(pos++, pubkey.priFingerprint);
        insert_into_pubkey_stmt->setInt(pos++, pubkey.pubAlgorithm);
        insert_into_pubkey_stmt->setString(pos++, pubkey.creationTime);
        insert_into_pubkey_stmt->setString(pos++, pubkey.expirationTime);
        
        for (const auto &v: pubkey.algValue){
            insert_into_pubkey_stmt->setBlob(pos++, v);
        }
        insert_into_pubkey_stmt->setString(pos++, pubkey.curve);
        insert_into_pubkey_stmt->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "write_pubkey_table FAILED, the key not have the results of the unpacking in the database! - %s", e.what());
    }
}


void DBManager::write_userID_csv(const DBStruct::userID &uid) {
    try{
        ostringstream f;
        f << '"' << uid.ownerkeyID << "\",";
        f << '"' << hexlify(uid.fingerprint) << "\",";
        f << '"' << ascii2radix64(uid.name) << "\",";
        f << "\n";
        FILEMANAGER.write(file_list.at(Utils::TABLES::USERID), f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userID_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}

void DBManager::write_userID_table(const DBStruct::userID &uid) {
    try{
        int pos = 1;
        insert_into_userid_stmt->setString(pos++, uid.ownerkeyID);
        insert_into_userid_stmt->setString(pos++, uid.fingerprint);
        insert_into_userid_stmt->setString(pos++, uid.name);
        insert_into_userid_stmt->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userID_table FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}

void DBManager::write_userAttributes_csv(const DBStruct::userAtt &ua) {
    try{
        ostringstream f;
        f << '"' << to_string(ua.id) << "\",";
        f << '"' << hexlify(ua.fingerprint) << "\",";
        f << '"' << ascii2radix64(ua.name) << "\",";
        f << '"' << ua.encoding << "\",";
        f << '"' << hexlify(ua.image) << "\",";
        f << "\n";
        FILEMANAGER.write(file_list.at(Utils::TABLES::USER_ATTRIBUTES), f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userAttributes_csv FAILED, the UserID not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}

void DBManager::write_userAttributes_table(const DBStruct::userAtt &ua) {
    int pos = 1;
    try{
        insert_into_userattributes_stmt->setInt(pos++, ua.id);
        insert_into_userattributes_stmt->setString(pos++, ua.fingerprint);
        insert_into_userattributes_stmt->setString(pos++, ua.name);
        insert_into_userattributes_stmt->setInt(pos++, ua.encoding);
        insert_into_userattributes_stmt->setBlob(pos++, ua.image);
        insert_into_userattributes_stmt->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userAttributes_table FAILED, the UserID not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}


void DBManager::write_signature_csv(const DBStruct::signatures &ss) {
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
        f << '"' << ascii2radix64(ss.signedUsername) << "\",";
        f << '"' << ascii2radix64(ss.issuingUsername) << "\",";
        f << '"' << ss.uatt_id << "\",";
        f << '"' << ascii2radix64(ss.regex) << "\",";
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
        f << '"' << ascii2radix64(ss.revocationReason) << "\",";
        f << '"' << ss.revocationSigId << "\",";
        f << '"' << ss.isRevocable << "\",";
        f << '"' << ss.isExportable << "\",";
        f << '"' << ss.isExpired << "\",";
        f << '"' << ss.isRevocation << "\",";
        f << "\n";
        FILEMANAGER.write(file_list.at(Utils::TABLES::SIGNATURE), f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}

void DBManager::write_signature_table(const DBStruct::signatures &ss) {
    int pos = 1;
    try{
        insert_into_signature_stmt->setInt(pos++, ss.type);
        insert_into_signature_stmt->setInt(pos++, ss.pubAlgorithm);
        insert_into_signature_stmt->setInt(pos++, ss.hashAlgorithm);
        insert_into_signature_stmt->setInt(pos++, ss.version);
        insert_into_signature_stmt->setString(pos++, ss.issuingKeyId);
        insert_into_signature_stmt->setString(pos++, ss.signedKeyId);
        insert_into_signature_stmt->setString(pos++, ss.issuingFingerprint);
        insert_into_signature_stmt->setString(pos++, ss.signedFingerprint);
        insert_into_signature_stmt->setString(pos++, ss.signedUsername);
        insert_into_signature_stmt->setString(pos++, ss.issuingUsername);
        insert_into_signature_stmt->setString(pos++, ss.uatt_id);
        insert_into_signature_stmt->setString(pos++, ss.regex);
        insert_into_signature_stmt->setString(pos++, ss.creationTime);
        insert_into_signature_stmt->setString(pos++, ss.expirationTime);
        insert_into_signature_stmt->setBlob(pos++, ss.rString);
        insert_into_signature_stmt->setBlob(pos++, ss.sString);
        insert_into_signature_stmt->setBlob(pos++, ss.flags);
        insert_into_signature_stmt->setString(pos++, ss.hashHeader);
        insert_into_signature_stmt->setBlob(pos++, ss.signedHash);
        insert_into_signature_stmt->setInt(pos++, ss.hashMismatch);
        insert_into_signature_stmt->setString(pos++, ss.keyExpirationTime);
        insert_into_signature_stmt->setInt(pos++, ss.revocationCode);
        insert_into_signature_stmt->setString(pos++, ss.revocationReason);
        insert_into_signature_stmt->setInt(pos++, ss.revocationSigId);
        insert_into_signature_stmt->setInt(pos++, ss.isRevocable);
        insert_into_signature_stmt->setInt(pos++, ss.isExportable);
        insert_into_signature_stmt->setInt(pos++, ss.isExpired);
        insert_into_signature_stmt->setInt(pos++, ss.isRevocation);
        insert_into_signature_stmt->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "write_signature_table FAILED, the signature not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}

void DBManager::write_self_signature_csv(const DBStruct::signatures &ss) {
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
        f << '"' << ascii2radix64(ss.signedUsername) << "\",";
        f << "\n";
        FILEMANAGER.write(file_list.at(Utils::TABLES::SELF_SIGNATURE), f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_self_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}

void DBManager::write_self_signature_table(const DBStruct::signatures &ss) {
    int pos = 1;
    try{
        insert_into_selfsignature_stmt->setInt(pos++, ss.type);
        insert_into_selfsignature_stmt->setInt(pos++, ss.pubAlgorithm);
        insert_into_selfsignature_stmt->setInt(pos++, ss.hashAlgorithm);
        insert_into_selfsignature_stmt->setInt(pos++, ss.version);
        insert_into_selfsignature_stmt->setString(pos++, ss.issuingKeyId);
        insert_into_selfsignature_stmt->setString(pos++, ss.issuingFingerprint);
        insert_into_selfsignature_stmt->setString(pos++, ss.preferedHash);
        insert_into_selfsignature_stmt->setString(pos++, ss.preferedCompression);
        insert_into_selfsignature_stmt->setString(pos++, ss.preferedSymmetric);
        insert_into_selfsignature_stmt->setInt(pos++, ss.trustLevel);
        insert_into_selfsignature_stmt->setString(pos++, ss.keyExpirationTime);
        insert_into_selfsignature_stmt->setInt(pos++, ss.isPrimaryUserId);
        insert_into_selfsignature_stmt->setString(pos++, ss.signedUsername);
        insert_into_selfsignature_stmt->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "write_self_signature_table FAILED, the signature not have the results of the unpacking in the database! - %s",
                          e.what());
    }
}


void DBManager::write_unpackerErrors_csv(const DBStruct::Unpacker_errors &mod){
    try{
        ostringstream f;
        for (const auto &c: mod.comments){
            f << '"' << mod.version << "\",";
            f << '"' << hexlify(mod.fingerprint) << "\"";
            f << '"' << c << "\",";
            f << "\n";
        }
        FILEMANAGER.write(file_list.at(Utils::TABLES::UNPACKER_ERRORS), f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_unpackerErrors_csv FAILED, the error of the unpacking will not be in the database! - %s",
                          e.what());
    }
}

void DBManager::write_unpackerErrors_table(const DBStruct::Unpacker_errors &mod){
    try{
        for (const auto &c: mod.comments){
            int pos = 1;
            insert_into_unpackererrors_stmt->setInt(pos++, mod.version);
            insert_into_unpackererrors_stmt->setString(pos++, mod.fingerprint);
            insert_into_unpackererrors_stmt->setString(pos++, c);
            insert_into_unpackererrors_stmt->execute();
        }
    }catch (exception &e){
        syslog(LOG_CRIT, "write_unpackerErrors_table FAILED, the error of the unpacking will not be in the database! - %s",
                          e.what());
    }
}




pair<std::string, std::string> DBManager::insert_pubkey_stmt = std::make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE Pubkey FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES TERMINATED BY '\\n' "
                                     "(keyId,version,@hexfingerprint,@hexpriFingerprint,pubAlgorithm,creationTime,@vexpirationTime,"
                                     "@hexe,@hexn,@hexp,@hexq,@hexg,@hexy,curveOID) SET fingerprint = UNHEX(@hexfingerprint),"
                                     "PriFingerprint = UNHEX(@hexpriFingerprint), e = UNHEX(@hexe), n = UNHEX(@hexn),"
                                     "p = UNHEX(@hexp), q = UNHEX(@hexq), g = UNHEX(@hexg), y = UNHEX(@hexy), "
                                     "expirationTime = nullif(@vexpirationTime, '');");

pair<std::string, std::string> DBManager::insert_signature_stmt = std::make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE Signatures FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES TERMINATED BY '\\n' "
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

pair<std::string, std::string> DBManager::insert_unpacked_stmt = std::make_pair<string, string>(
                    "LOAD DATA LOCAL INFILE '", "' IGNORE INTO TABLE tmp_unpacker FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
                    "LINES TERMINATED BY '\\n' (version,@hexfingerprint,unpacked) SET fingerprint = UNHEX(@hexfingerprint);");

string DBManager::create_unpacker_tmp_table = "CREATE TEMPORARY TABLE tmp_unpacker (version tinyint, fingerprint binary(20), unpacked tinyint);";
string DBManager::update_gpg_keyserver = "UPDATE gpg_keyserver INNER JOIN tmp_unpacker ON tmp_unpacker.version = gpg_keyserver.version AND tmp_unpacker.fingerprint = gpg_keyserver.fingerprint SET gpg_keyserver.is_unpacked = tmp_unpacker.unpacked;";
string DBManager::drop_unpacker_tmp_table = "DROP TEMPORARY TABLE tmp_unpacker;";


    pair<std::string, std::string> DBManager::insert_self_signature_stmt = std::make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE selfSignaturesMetadata FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES TERMINATED BY '\\n' "
                                     "(type,pubAlgorithm,hashAlgorithm,version,issuingKeyId,@hexissuingFingerprint,"
                                     "@hexpreferedHash,@hexpreferedCompression,@hexpreferedSymmetric,trustLevel,@vkeyExpirationTime,"
                                     "isPrimaryUserId,@base64signedUserId) SET issuingFingerprint = UNHEX(@hexissuingFingerprint), "
                                     "preferedSymmetric = UNHEX(@hexpreferedSymmetric), preferedCompression = UNHEX(@hexpreferedCompression), "
                                     "preferedHash = UNHEX(@hexpreferedHash), keyExpirationTime = nullif(@vkeyExpirationTime, ''), signedUserID = FROM_BASE64(@base64signedUserID);");

    pair<std::string, std::string> DBManager::insert_userID_stmt = std::make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE UserID FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES TERMINATED BY '\\n' (ownerkeyID,@hexfingerprint,@base64name) "
                                     "SET fingerprint = UNHEX(@hexfingerprint), name = FROM_BASE64(@base64name);");

    pair<std::string, std::string> DBManager::insert_userAtt_stmt = std::make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE UserAttribute FIELDS TERMINATED BY ',' ENCLOSED BY '\"'"
                                     "LINES TERMINATED BY '\\n' (id,@hexfingerprint,@base64name,encoding,@heximage) "
                                     "SET fingerprint = UNHEX(@hexfingerprint), name = FROM_BASE64(@base64name), image = UNHEX(@heximage);");

    pair<std::string, std::string> DBManager::insert_unpackerErrors_stmt = std::make_pair<string, string>("LOAD DATA LOCAL INFILE '",
                                     "' IGNORE INTO TABLE Unpacker_errors FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
                                     "LINES TERMINATED BY '\\n' (version,@hexfingerprint,error) "
                                     "SET fingerprint = UNHEX(@hexfingerprint);");

    pair<std::string, std::string> DBManager::insert_certificate_stmt = std::make_pair<string, string>(
            "LOAD DATA LOCAL INFILE '", "' IGNORE INTO TABLE gpg_keyserver FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
            "LINES TERMINATED BY '\\n' (version,keyId,@hexfingerprint,hash,is_unpacked,error_code,filename,origin,len) "
            "SET fingerprint = UNHEX(@hexfingerprint)");




DBQuery::DBQuery(sql::Connection * con, const std::string & stmt_):
    query(stmt_),
    stmt(std::shared_ptr<sql::PreparedStatement>(con->prepareStatement(stmt_)))
{
}

void DBQuery::refresh(sql::Connection * con){
    stmt = std::shared_ptr<sql::PreparedStatement>(con->prepareStatement(query));
}

DBQuery::~DBQuery(){
    for(auto & p: trash_bin)
        delete p;
}

void DBQuery::setString(const int pos, const string & str){
    stmt->setString(pos, str);
    params[pos] = str;
}

void DBQuery::setBlob(const int pos, const string & s){
    std::stringstream * is = new std::stringstream(s);
    stmt->setBlob(pos,is);
}


void DBQuery::setBlob(const int pos, std::vector<unsigned char> & s){
    std::istringstream * is = new std::istringstream;
    is->rdbuf()->pubsetbuf(reinterpret_cast<char*>(&s[0]), s.size());
    stmt->setBlob(pos, is);
}

void DBQuery::setBlob(const int pos, istream * s_ptr){
    trash_bin.push_back(s_ptr);
    stmt->setBlob(pos, s_ptr);
}

void DBQuery::setInt(const int pos, const int num){
    stmt->setInt(pos, num);
    params[pos] = to_string(num);
}

void DBQuery::setBigInt(const int pos, const string & value){
    stmt->setBigInt(pos, value);
    params[pos] = value;
}

void DBQuery::setBoolean(const int pos, const bool value){
    stmt->setBoolean(pos, value);
    params[pos] = value ? "True" : "False";
}

unique_ptr<DBResult> DBQuery::execute(){
    syslog(LOG_DEBUG, "Execute prepared query %s", query.c_str());
    for(const auto& elem : params){
        syslog(LOG_DEBUG, "Param %d -> %s", elem.first, elem.second.c_str());
    }
    if (stmt->execute()){
        unique_ptr<DBResult> res = std::make_unique<DBResult>(stmt->getResultSet());
        return res;
    }
    for(auto & p: trash_bin)
        delete p;
    trash_bin.clear();
    return 0;
}

DBResult::DBResult(sql::ResultSet * res_):
    res(res_)
{
}

DBResult::~DBResult(){
    if (res != NULL)
        free(res);
}

bool DBResult::next(){
    return res->next();
}

string DBResult::getString(const std::string & attribute){
    return res->getString(attribute);
}

int DBResult::getInt(const string & attribute){
    return res->getInt(attribute);
}

unsigned int DBResult::getUInt(const string & attribute){
    return res->getUInt(attribute);
}

int DBResult::getInt(const int pos){
    return res->getInt(pos);
}

string DBResult::getString(const int pos){
    return res->getString(pos);
}

bool DBResult::getBoolean(const string & attribute){
    return res->getBoolean(attribute);
}

shared_ptr<std::istream> DBResult::getBlob(const std::string & attribute){
    return shared_ptr<std::istream>(res->getBlob(attribute));
}

long unsigned int DBResult::size(){
    return res->rowsCount();
}

}
}
