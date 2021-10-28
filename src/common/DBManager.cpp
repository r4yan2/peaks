#include "DBManager.h"
#include <boost/program_options/variables_map.hpp>
#include <cppconn/connection.h>
#include <sys/syslog.h>
#include <numeric>
#include <sstream>
#include "config.h"
#include <common/Thread_Pool.h>
#include <tuple>

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
    con = driver->connect(connection_properties);
}

void DBManager::connect_schema(){
    con->setSchema(CONTEXT.dbsettings.db_database);
    get_certificate_from_filestore_stmt = prepare_query("SELECT filename, origin, len FROM gpg_keyserver WHERE hash = (?)");
    get_filestore_index_from_stash_stmt = prepare_query("SELECT value FROM stash WHERE name = 'filestore_index'");
    store_filestore_index_to_stash_stmt = prepare_query("REPLACE INTO stash (name, value) VALUES ('filestore_index', ?)");
    // filestorage
    int idx = 0;
    try{
        std::unique_ptr<DBResult> result = get_filestore_index_from_stash_stmt->execute();
        while (result->next()){
            idx = atoi(result->getString("value").c_str());
        }
    }catch(std::exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    CONTEXT.filestorage_index = idx;
    std::string format = CONTEXT.dbsettings.filestorage_format;
    int sz = std::snprintf(nullptr, 0, format.c_str(), idx);
    std::vector<char> buf(sz + 1);
    std::snprintf(&buf[0], buf.size(), format.c_str(), idx);
    std::string tmp(buf.data(), buf.size());
    filestorage.open(tmp, true);

}

void DBManager::init_database(const std::string &filename){

    std::string dbinit = "CREATE DATABASE IF NOT EXISTS `" + CONTEXT.dbsettings.db_database + "`;";
    execute_query(dbinit);
    con->setSchema(CONTEXT.dbsettings.db_database);
    std::ifstream inFile;
    inFile.open(filename);
    if (inFile.fail())
    {
        std::cerr << "Could not find init file for DB" << std::endl;
    }
    std::stringstream buffer;
    buffer << inFile.rdbuf();
    execute_query(buffer.str());
    std::cerr << "Done init database" << std::endl;
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
    return connected;
}

void DBManager::begin_transaction(){
    try{
        execute_query("SET AUTOCOMMIT = 0");
        execute_query("START TRANSACTION");
    }catch (std::exception &e){
        syslog(LOG_WARNING, "begin transaction FAILED, data corruption may occur! - %s", e.what());
    }
}

void DBManager::end_transaction(){
    try{
        execute_query("COMMIT");
        execute_query("SET AUTOCOMMIT = 1");
    }catch (std::exception &e){
        syslog(LOG_WARNING, "begin transaction FAILED, data corruption may occur! - %s", e.what());
    }
}


void DBManager::lockTables(int selection){
    try{
        execute_query("SET AUTOCOMMIT = 0");
        execute_query("SET UNIQUE_CHECKS = 0");
        execute_query("SET sql_log_bin = 0");
        execute_query("SET foreign_key_checks = 0");

        std::string table = tables.at(selection);
        std::string lockQuery = std::string("LOCK TABLES ") + table + std::string(" WRITE");
        execute_query(lockQuery);
    }catch (std::exception &e){
        syslog(LOG_WARNING, "lock_tables_stmt FAILED, the query will be slower! - %s", e.what());
    }
}

void DBManager::unlockTables(){
    try{
        execute_query(("UNLOCK TABLES;"));
    }catch (std::exception &e){
        syslog(LOG_CRIT, "unlock_tables_stmt FAILED, the tables will remain locked! - %s",
                          e.what());
    }
}

std::shared_ptr<DBQuery> DBManager::prepare_query(const std::string & stmt){
    std::shared_ptr<sql::PreparedStatement> query = std::shared_ptr<sql::PreparedStatement>(con->prepareStatement(stmt));
    std::shared_ptr<DBQuery> res = std::make_shared<DBQuery>(query);
    return res; 
}

void DBManager::execute_query(const std::string & stmt){
    std::unique_ptr<sql::Statement>(con->createStatement())->execute(stmt);
}

std::tuple<std::string, int> DBManager::store_certificate_to_filestore(const std::string &certificate){
    if (filestorage.size() + certificate.size() > CONTEXT.dbsettings.filestorage_maxsize * 1024 * 1024){
        // create new file
        int idx = CONTEXT.filestorage_index + 1;
        std::string format = CONTEXT.dbsettings.filestorage_format;
        int sz = std::snprintf(nullptr, 0, format.c_str(), idx);
        std::vector<char> buf(sz + 1);
        std::snprintf(&buf[0], buf.size(), format.c_str(), idx);
        std::string tmp(buf.data(), buf.size());
        filestorage.open(tmp, true);
    try{
        store_filestore_index_to_stash_stmt->setInt(1, idx);
        store_filestore_index_to_stash_stmt->execute();
    }catch(std::exception &e){
        syslog(LOG_WARNING, "Could not update index value to DB: %s", e.what());
    }
        
    }
    std::size_t orig = filestorage.write(certificate);
    return std::make_tuple(filestorage.get_name(), orig);
}


std::string DBManager::get_certificate_from_filestore(const std::string &filename, const int start, const int length){
    std::shared_ptr<std::istream> file = get_certificate_stream_from_filestore(filename, start, length);
    std::string buffer(length, ' ');
    file->read(&buffer[0], length); 
    return buffer;
}

std::string DBManager::get_certificate_from_filestore(const std::string &hash){
    std::string filename;
    int start, length;
    try{
        get_certificate_from_filestore_stmt->setString(1, hash);
        std::unique_ptr<DBResult> result = get_certificate_from_filestore_stmt->execute();
        while(result->next()){
            filename = result->getString("filename");
            start = result->getInt("origin");
            length = result->getInt("len");
        }
    }catch(std::exception &e){
        syslog(LOG_WARNING, "Could not fetch cache from the DB: %s", e.what());
    }
    return get_certificate_from_filestore(filename, start, length);
}

std::shared_ptr<std::istream> DBManager::get_certificate_stream_from_filestore(const std::string &filename, const int start, const int length){
    std::shared_ptr<std::istream> file = std::make_shared<std::ifstream>(filename, std::ios::in | std::ios::binary);
    file->seekg(start);
    return file;
}

DBQuery::DBQuery(std::shared_ptr<sql::PreparedStatement> & stmt_):
    stmt(stmt_)
{
}

DBQuery::~DBQuery(){
    for(auto & p: trash_bin)
        delete p;
}

void DBQuery::setString(const int pos, const std::string & str){
    stmt->setString(pos, str);
}

void DBQuery::setBlob(const int pos, const std::string & s){
    std::istream * s_ptr = new std::istringstream(s);
    setBlob(pos, s_ptr);
}

void DBQuery::setBlob(const int pos, std::istream * s_ptr){
    trash_bin.push_back(s_ptr);
    stmt->setBlob(pos, s_ptr);
}

void DBQuery::setInt(const int pos, const int num){
    stmt->setInt(pos, num);
}

void DBQuery::setBigInt(const int pos, const std::string & value){
    stmt->setBigInt(pos, value);
}

void DBQuery::setBoolean(const int pos, const bool value){
    stmt->setBoolean(pos, value);
}

std::unique_ptr<DBResult> DBQuery::execute(){
    if (stmt->getMetaData()->getColumnCount()){
        std::unique_ptr<sql::ResultSet> res = std::unique_ptr<sql::ResultSet>(stmt->executeQuery());
        return std::make_unique<DBResult>(res);
    }
    else{
        stmt->execute();
        return 0;
    }
}

DBResult::DBResult(std::unique_ptr<sql::ResultSet> & res_):
    res(std::move(res_))
{}

DBResult::~DBResult(){
}

bool DBResult::next(){
    return res->next();
}

std::string DBResult::getString(const std::string & attribute){
    return res->getString(attribute);
}

int DBResult::getInt(const std::string & attribute){
    return res->getInt(attribute);
}

unsigned int DBResult::getUInt(const std::string & attribute){
    return res->getUInt(attribute);
}

int DBResult::getInt(const int pos){
    return res->getInt(pos);
}

std::string DBResult::getString(const int pos){
    return res->getString(pos);
}

bool DBResult::getBoolean(const std::string & attribute){
    return res->getBoolean(attribute);
}

std::shared_ptr<std::istream> DBResult::getBlob(const std::string & attribute){
    return std::shared_ptr<std::istream>(res->getBlob(attribute));
}

long unsigned int DBResult::size(){
    return res->rowsCount();
}

}
}
