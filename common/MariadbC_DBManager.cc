#include "DBManager.h"
#include <stddef.h>
#include <string.h>
#include <sstream>

struct membuf : std::streambuf
{
    membuf(char* begin, unsigned int length) {
        this->setg(begin, begin, begin+length);
    }
};

DBManager::DBManager(const DBSettings & settings_):
    settings(settings_),
    con(mysql_init(NULL))
{
    if (mysql_real_connect(con, settings.db_host.c_str(), settings.db_user.c_str(), settings.db_password.c_str(), settings.db_database.c_str(), 0, NULL, 0) == NULL)
        throw std::runtime_error("connection to database failed");
}

DBManager::~DBManager(){
    mysql_close(con);
}

bool DBManager::ensure_database_connection(){
    bool connected = con != NULL;

    if (connected)
        return connected;

    con = mysql_init(NULL);
    if (con == NULL){
        throw std::runtime_error("failed to acquire connection handler");
    }

    if (mysql_real_connect(con, settings.db_host.c_str(), settings.db_user.c_str(), settings.db_password.c_str(), settings.db_database.c_str(), 0, NULL, 0) == NULL){
        throw std::runtime_error("connection to database failed");
    }
    my_bool reconnect = 0;
    mysql_options(con, MYSQL_OPT_RECONNECT, &reconnect);
    return connected;
}

std::shared_ptr<DBQuery> DBManager::prepare_query(const std::string & query){
    MYSQL_STMT * stmt = mysql_stmt_init(con);
    if (!stmt){
        fprintf(stderr, " mysql_stmt_init(), out of memory\n");
        exit(0);
    }
    std::string * data = new std::string(query);
    int err = mysql_stmt_prepare(stmt, data->c_str(), data->size());
    if (err){
        fprintf(stderr, " mysql_stmt_prepare() failed with error n %d\n", err);
        fprintf(stderr, " %s\n%s\n", mysql_stmt_error(stmt), mysql_error(con));
        exit(0);
    }
    std::shared_ptr<DBQuery> res = std::make_shared<DBQuery>(stmt, con); 
    return res;
}

void DBManager::execute_query(const std::string & stmt){
    /*
    MYSQL_STMT * query = mysql_stmt_init(con);
    if (!query){
        fprintf(stderr, " mysql_stmt_init(), out of memory\n");
        exit(0);
    }
    if (mysql_stmt_prepare(query, stmt.c_str(), stmt.size())){
        fprintf(stderr, " mysql_stmt_prepare() failed\n");
        fprintf(stderr, " %s\n", mysql_stmt_error(query));
        exit(0);
    }
    DBQuery res(query); 
    return res.execute();
    */
    mysql_real_query(con, stmt.c_str(), stmt.size());
}

DBQuery::DBQuery(MYSQL_STMT * stmt_, MYSQL * conn_):
    stmt(stmt_),
    param_count(mysql_stmt_param_count(stmt_)),
    max_allowed_packet(0),
    bind_vect(new MYSQL_BIND[param_count]),
    chunks()
{
    mysql_get_option(conn_, MYSQL_OPT_MAX_ALLOWED_PACKET, &max_allowed_packet);
    memset(bind_vect, 0, sizeof(MYSQL_BIND)*param_count);
}

DBQuery::~DBQuery(){
}

void DBQuery::setBlob(int pos, const std::string & s){
    pos--;
    MYSQL_BIND * bind = &bind_vect[pos];
    bind->buffer_type = MYSQL_TYPE_BLOB;
    bind->buffer = 0;
    //bind->buffer_length = s.size();
    bind->is_null = 0;
    bind->length = new unsigned long(s.size());
    param_count--;
    int iter = max_allowed_packet ? s.size() / max_allowed_packet : 0;
    for(int i=0; i<iter; i++)
        chunks.push_back(
                std::make_pair(pos, s.substr(i*max_allowed_packet, max_allowed_packet))
                );

    unsigned long last_chunk_size = s.size() - iter * max_allowed_packet;
    chunks.push_back(
            std::make_pair(pos, s.substr(iter*max_allowed_packet, last_chunk_size))
            );

}

void DBQuery::setBlob(int pos, std::istream * ss){
    std::string content{ std::istreambuf_iterator<char>(*ss),
                             std::istreambuf_iterator<char>() };
    setBlob(pos, content);
}

void DBQuery::setBoolean(int pos, const bool value){
    setInt(pos, value);
}

void DBQuery::setString(int pos, const std::string & str){
    pos--;
    MYSQL_BIND * bind = &bind_vect[pos];
    bind->buffer_type = MYSQL_TYPE_STRING;
    std::string * data = new std::string(str);
    bind->buffer = (void *) data->c_str();
    bind->buffer_length = data->size();
    bind->length = &(bind->buffer_length);
    //bind->is_null = 0;
    bind->error = new my_bool;
    param_count--;
}


void DBQuery::setInt(int pos, const int num){
    pos--;
    MYSQL_BIND * bind = &bind_vect[pos];
    bind->buffer_type = MYSQL_TYPE_LONG;
    bind->buffer = (void *) new int(num);
    bind->buffer_length = sizeof(num);
    bind->is_null = 0;
    bind->length = 0;
    bind->error = 0;
    param_count--;
}

void DBQuery::setBigInt(int pos, const std::string & value){
    setString(pos, value);
}

std::unique_ptr<DBResult> DBQuery::execute(){
    if (param_count > 0)
        throw std::runtime_error("Not all parameters setted!");
    mysql_stmt_bind_param(stmt, bind_vect);
    for (auto &c: chunks){
        int pos = c.first;
        std::string data = c.second;
        mysql_stmt_send_long_data(stmt, pos, data.c_str(), data.size());
    }
    std::unique_ptr<DBResult> res = std::make_unique<DBResult>(stmt);
    return res;
}

DBResult::DBResult(MYSQL_STMT * stmt_):
    stmt(stmt_)
{
    MYSQL_RES * meta_result = mysql_stmt_result_metadata(stmt);
	if (!meta_result)
	{
	  fprintf(stderr,
	         " mysql_stmt_result_metadata(), \
	           returned no meta information\n");
	  fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
	  exit(0);
	}
    MYSQL_FIELD * field = mysql_fetch_fields(meta_result);
    int column_count = mysql_num_fields(meta_result);
    bind_vect = new MYSQL_BIND[column_count];
    memset(bind_vect, 0, sizeof(MYSQL_BIND)*column_count);
    mysql_stmt_attr_set(stmt, STMT_ATTR_UPDATE_MAX_LENGTH, new bool(1));
    mysql_stmt_execute(stmt);
    for (int i=0; i<column_count; i++){
        field_map[std::string(field[i].name)] = i;
        bind_vect[i].buffer_type = field[i].type;
        //bind_vect[i].buffer = (void*) 'A';
        //bind_vect[i].buffer_length = 0;
        bind_vect[i].length = new unsigned long();
        bind_vect[i].is_null = new my_bool();
        bind_vect[i].error = new my_bool();
        bind_vect[i].u.indicator = new char();
    }
    mysql_stmt_bind_result(stmt, bind_vect);
    mysql_stmt_store_result(stmt);

    for (int i=0; i<field_map.size(); i++){
        unsigned int size = field[i].max_length;
        //fprintf(stderr, "%s\t%u\t%lu\n", field[i].name, size, field[i].length);
        //size = size ? size : field[i].length;
        //size = size + 32;
        fprintf(stderr, "%s\t%u\n", field[i].name, size);
        bind_vect[i].buffer = malloc(size);
        fprintf(stderr, "%p\n", (void *) bind_vect[i].buffer);
        bind_vect[i].buffer_length = size;
        memset(bind_vect[i].buffer, 0, size);
    }
    mysql_stmt_bind_result(stmt, bind_vect);
    mysql_free_result(meta_result);
    /*
    next();
    for (int i=0; i<column_count; i++){
        bind_vect[i].buffer = malloc(*bind_vect[i].length);
        bind_vect[i].buffer_length = *bind_vect[i].length;
        mysql_stmt_fetch_column(stmt, &bind_vect[i], i, 0);
    }
    */
}

unsigned long DBResult::size(){
    return mysql_stmt_num_rows(stmt);
}

DBResult::~DBResult(){
    /*
    for (int i=0; i < field_map.size(); i++){
        free(bind_vect[i].buffer);
        delete bind_vect[i].length;
        delete bind_vect[i].is_null;
        delete bind_vect[i].error;
    }
    delete bind_vect;
    */
    mysql_stmt_close(stmt);
}

bool DBResult::next(){
    return !mysql_stmt_fetch(stmt);
}

std::string DBResult::getString(const std::string & attribute){
    const int col = field_map.at(attribute);
    return getString(col);
}

std::string DBResult::getString(const int col){
    if (*bind_vect[col].is_null)
        return "";
    char * start = (char*) bind_vect[col].buffer;
    size_t size = *(bind_vect[col].length);
    return std::string(start, size);
}

int DBResult::getInt(const std::string & attribute){
    int col = field_map.at(attribute);
    if (*bind_vect[col].is_null)
        return 0;
    int * res = (int*)bind_vect[col].buffer;
    return *res;
}

unsigned int DBResult::getUInt(const std::string & attribute){
    int col = field_map.at(attribute);
    if (*bind_vect[col].is_null)
        return 0;
    return *(unsigned int*) bind_vect[col].buffer;
}

int DBResult::getInt(const int col){
    return *(int *)bind_vect[col].buffer;
}

bool DBResult::getBoolean(const std::string & attribute){
    int col = field_map.at(attribute);
    if (*bind_vect[col].is_null)
        return false;
    return *(bool *)bind_vect[col].buffer;
}

std::istream * DBResult::getBlob(const std::string & attribute){
    int col = field_map.at(attribute);
    //TODO Add proper handling
    //if (*bind_vect[col].is_null)
    //    return new std::istream();
    char * buf = (char*) bind_vect[col].buffer;
    unsigned long length = * bind_vect[col].length;
    membuf sbuf(buf, length);
    return new std::istream(&sbuf);

}
