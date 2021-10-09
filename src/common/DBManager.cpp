#include "DBManager.h"
#include <boost/program_options/variables_map.hpp>
#include <cppconn/connection.h>
#include <sys/syslog.h>
#include <numeric>
#include <sstream>
#include "config.h"

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
}

void DBManager::init_database(const std::string &filename){

    std::string dbinit = "CREATE DATABASE IF NOT EXISTS `" + CONTEXT.dbsettings.db_database + "`;";
    execute_query(dbinit);
    connect_schema();
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

void DBManager::lockTables(int selection){
    try{
        execute_query("SET AUTOCOMMIT = 0");
        execute_query("SET UNIQUE_CHECKS = 0");
        execute_query("SET sql_log_bin = 0");
        execute_query("SET foreign_key_checks = 0");

        std::string table = tables.at(selection);
        //std::string s = std::accumulate(++tables.begin(), tables.end(), tables[0], [](std::string& a, std::string& b){return a + std::string(" WRITE, ") + b;});

        std::string lockQuery = std::string("LOCK TABLES ") + table + std::string(" WRITE");
        execute_query(lockQuery);
    }catch (std::exception &e){
        syslog(LOG_WARNING, "lock_tables_stmt FAILED, the query will be slowly! - %s", e.what());
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
