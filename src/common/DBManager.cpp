#include "DBManager.h"
#include <cppconn/connection.h>
#include <sys/syslog.h>
#include <numeric>
#include <sstream>
#include "config.h"
#include <common/FileManager.h>
#include <common/Thread_Pool.h>
#include <tuple>

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
    connection_properties["OPT_CHARSET_NAME"] = "utf8";
    connection_properties["OPT_SET_CHARSET_NAME"] = "utf8";
    connection_properties["OPT_LOCAL_INFILE"] = 1;
    con = driver->connect(connection_properties);
}

void DBManager::connect_schema(){
    con->setSchema(CONTEXT.dbsettings.db_database);
    get_certificate_from_filestore_stmt = prepare_query("SELECT filename, origin, len FROM gpg_keyserver WHERE hash = (?)");
    get_filestore_index_from_stash_stmt = prepare_query("SELECT value FROM stash WHERE name = 'filestore_index'");
    store_filestore_index_to_stash_stmt = prepare_query("REPLACE INTO stash (name, value) VALUES ('filestore_index', ?)");
    get_from_cache_stmt = prepare_query("SELECT value, ((created + INTERVAL (?) day) < NOW()) as expired FROM stash WHERE name = (?)");
    set_in_cache_stmt = prepare_query("REPLACE INTO stash(`name`,`value`, `created`) VALUES (?, ?, NOW())");
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
    try{
        CONTEXT.critical_section = true;
        execute_query("SET AUTOCOMMIT = 0");
        execute_query("SET UNIQUE_CHECKS = 0");
        execute_query("SET sql_log_bin = 0");
        execute_query("SET foreign_key_checks = 0");
        execute_query("START TRANSACTION");
    }catch (exception &e){
        syslog(LOG_WARNING, "begin transaction FAILED, data corruption may occur! - %s", e.what());
    }
}

void DBManager::end_transaction(){
    try{
        CONTEXT.critical_section = false;
        execute_query("COMMIT");
        execute_query("SET AUTOCOMMIT = 1");
        execute_query("SET UNIQUE_CHECKS = 1");
        execute_query("SET sql_log_bin = 1");
        execute_query("SET foreign_key_checks = 1");
    }catch (exception &e){
        syslog(LOG_WARNING, "end transaction FAILED, data corruption may occur! - %s", e.what());
    }
}

void DBManager::rollback_transaction(){
    try{
        CONTEXT.critical_section = false;
        execute_query("ROLLBACK");
        execute_query("SET AUTOCOMMIT = 1");
        execute_query("SET UNIQUE_CHECKS = 1");
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
    syslog(LOG_INFO, "Execute query %s", stmt.c_str());
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
    return get_certificate_from_filestore(filename, start, length);
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

bool DBManager::get_from_cache(const string &key, std::string &value){
    string res = "";
    bool expired = false;
    try{
        get_from_cache_stmt->setInt(1, CONTEXT.dbsettings.expire_interval);
        get_from_cache_stmt->setString(2, key);
        unique_ptr<DBResult> result = get_from_cache_stmt->execute();
        while (result->next()){
            value = result->getString("value");
            expired = result->getBoolean("expired");
        }
    }catch(exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    return expired;

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
    for (const auto &it: file_list){
        string f = Utils::get_file_name(CONTEXT.dbsettings.tmp_folder, it.first);
        auto table = it.first;
        FILEMANAGER.closeFile(it.second);
        begin_transaction();
        insertCSV(f, table);
        end_transaction();
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
    // Delete inserted file
    if (CONTEXT.vm.count("noclean") == 0){
        try{
            remove(f.c_str());
        }catch (exception &e){
            syslog(LOG_CRIT, "Error during deletion of files. The file will remaining in the temp folder. - %s",
                              e.what());
        }
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
            "LINES TERMINATED BY '\\n' (version,ID,@hexfingerprint,hash,is_unpacked,error_code,filename,origin,len) "
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
}

void DBQuery::setBlob(const int pos, const string & s){
    istream * s_ptr = new std::istringstream(s);
    setBlob(pos, s_ptr);
}

void DBQuery::setBlob(const int pos, istream * s_ptr){
    trash_bin.push_back(s_ptr);
    stmt->setBlob(pos, s_ptr);
}

void DBQuery::setInt(const int pos, const int num){
    stmt->setInt(pos, num);
}

void DBQuery::setBigInt(const int pos, const string & value){
    stmt->setBigInt(pos, value);
}

void DBQuery::setBoolean(const int pos, const bool value){
    stmt->setBoolean(pos, value);
}

unique_ptr<DBResult> DBQuery::execute(){
    syslog(LOG_INFO, "Execute prepared query %s", query.c_str());
    if (stmt->execute()){
        unique_ptr<DBResult> res = std::make_unique<DBResult>(stmt->getResultSet());
        return res;
    }
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
