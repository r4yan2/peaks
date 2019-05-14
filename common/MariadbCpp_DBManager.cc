#include "DBManager.h"
#include <sstream>
#include <iostream>
#include <mariadb++/date_time.hpp>

DBManager::DBManager(const DBSettings & settings_):
    settings(settings_),
    acc(account::create(settings.db_host, settings.db_user, settings.db_password, settings.db_database)),
    con(connection::create(acc))
{}

DBManager::~DBManager()
{}

bool DBManager::ensure_database_connection(){
    bool connected = con != NULL && con->connected();
    if (connected)
        return connected;

    con = connection::create(acc);
    return connected;
}

std::shared_ptr<DBQuery> DBManager::prepare_query(const std::string & stmt){
    statement_ref query = con->create_statement(stmt);
    std::shared_ptr<DBQuery> res = std::make_shared<DBQuery>(query);
    return res; 
}

void DBManager::execute_query(const std::string & stmt){
    con->execute(stmt);
}

DBQuery::DBQuery(statement_ref & stmt_):
    stmt(stmt_)
{
}

DBQuery::~DBQuery()
{}

void DBQuery::setString(const int pos, const std::string & str){
    stmt->set_string(pos-1, str);
}

void DBQuery::setBlob(const int pos, const std::string & s){
    std::istream * s_ptr = new std::istringstream(s);
    setBlob(pos, s_ptr);
}

void DBQuery::setBlob(const int pos, std::istream * s_ptr){
    stmt->set_blob(pos-1, std::shared_ptr<std::istream>(s_ptr));
}

void DBQuery::setInt(int pos, int value){
    stmt->set_signed32(pos-1, value);
}

void DBQuery::setBigInt(const int pos, const std::string & value){
    stmt->set_string(pos-1, value);
}

void DBQuery::setBoolean(const int pos, const bool value){
    stmt->set_boolean(pos-1, value);
}

std::unique_ptr<DBResult> DBQuery::execute(){
    result_set_ref res = stmt->query();
    if (res)
        return std::make_unique<DBResult>(res);
    return 0;
}

DBResult::DBResult(result_set_ref & res_):
    res(std::move(res_))
{}

DBResult::~DBResult(){
}

bool DBResult::next(){
    return res->next();
}

std::string DBResult::getString(const std::string & attribute){
    if (res->get_is_null(attribute)){
        return "";
    }
    int idx = res->column_index(attribute);
    if (idx == -1)
        throw std::runtime_error("Attribute not found: "+attribute);
    return getString(idx);
}

int DBResult::getInt(const std::string & attribute){
    return getInt(res->column_index(attribute));
}

long unsigned int DBResult::getBigInt(const std::string & attribute){
    return res->get_unsigned64(attribute);
}

unsigned int DBResult::getUInt(const std::string & attribute){
    return res->get_unsigned32(attribute);
}

int DBResult::getInt(int pos){
    value::type res_type = res->column_type(pos);
    switch(res_type){
        case value::type::boolean:
        case value::type::unsigned8:
            return (int) res->get_unsigned8(pos);
        case value::type::signed8:
            return (int) res->get_signed8(pos);
        case value::type::unsigned16:
            return (int) res->get_unsigned16(pos);
        case value::type::signed16:
            return (int) res->get_signed16(pos);
        case value::type::signed32:
            return (int) res->get_signed32(pos);
        default:
            throw std::runtime_error("could not determine int type");

    }
}

std::string DBResult::getString(int pos){
    value::type ret_type = res->column_type(pos);

    if (ret_type >= value::type::unsigned8 and ret_type <= value::type::signed16 or ret_type == value::type::signed32 or ret_type == value::type::boolean){
        int ret = getInt(pos);
        std::ostringstream str_ret;
        str_ret << ret;
        return str_ret.str();
    }
    if (ret_type == value::type::unsigned32){
        unsigned int ret = res->get_unsigned32(pos);
        std::ostringstream str_ret;
        str_ret << ret;
        return str_ret.str();
    }

    if (ret_type == value::type::unsigned64){
        long unsigned int ret = res->get_unsigned64(pos);
        std::ostringstream str_ret;
        str_ret << ret;
        return str_ret.str();
    }
    if (ret_type == value::type::date_time){
        date_time ret = res->get_date_time(pos);
        return ret.str_date();
    }
    return res->get_string(pos);
}

bool DBResult::getBoolean(const std::string & attribute){
    return res->get_boolean(attribute);
}

std::shared_ptr<std::istream> DBResult::getBlob(const std::string & attribute){
    return res->get_blob(attribute);
}

long unsigned int DBResult::size(){
    return res->row_count();
}
