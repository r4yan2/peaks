#include "DBManager.h"
#include <sstream>

DBManager::DBManager(const DBSettings & settings_):
    settings(settings_),
    driver(get_driver_instance()),
    con(driver->connect(settings.db_host, settings.db_user, settings.db_password))
{
    con->setSchema(settings.db_database);
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
    con = std::shared_ptr<sql::Connection>(driver->connect(settings.db_host, settings.db_user, settings.db_password));
    con->setSchema(settings.db_database);
    return connected;
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
