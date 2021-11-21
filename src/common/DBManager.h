#ifndef DBMANAGER_H
#define DBMANAGER_H

#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>

#include <memory>
#include <vector>
#include <string>

#include <common/utils.h>
#include <common/Thread_Pool.h>
#include "DBStruct.h"

namespace peaks{
namespace common{

struct DBSettings{
    std::string db_user;
    std::string db_password;
    std::string db_host;
    int db_port;
    std::string db_database;
    std::string tmp_folder;
    std::string error_folder;
    std::string filestorage_format;
    int filestorage_maxsize;
    int expire_interval;
};

class DBResult {
    private:
        std::unique_ptr<sql::ResultSet> res;
    public:
        DBResult(std::unique_ptr<sql::ResultSet> &);
        ~DBResult();
        bool next();
        std::string getString(const std::string & attribute);
        int getInt(const std::string & attribute);
        long unsigned int getBigInt(const std::string & attribute);
        unsigned int getUInt(const std::string & attribute);
        int getInt(int);
        std::string getString(int);
        bool getBoolean(const std::string & attribute);
        std::shared_ptr<std::istream> getBlob(const std::string & attribute);
        long unsigned int size();
};

class DBQuery {
    private:
        std::shared_ptr<sql::PreparedStatement> stmt;
        std::vector<std::istream *> trash_bin;

    public:

        DBQuery(std::shared_ptr<sql::PreparedStatement> & stmt_);
        ~DBQuery();

        std::unique_ptr<DBResult> execute();
        void setBlob(int, const std::string &);
        void setBlob(int, std::istream *);
        void setBoolean(int, const bool);
        void setString(int, const std::string &);
        void setBigInt(int, const std::string &);
        void setInt(int, int);
};

class DBManager {
    public:
        std::map<int, std::string> tables;
    private:
        sql::Driver *driver;
        sql::Connection *con;
        sql::ConnectOptionsMap connection_properties;
        std::shared_ptr<DBQuery>
            get_from_cache_stmt,
            set_in_cache_stmt,
            get_certificate_from_filestore_stmt,
            get_filestore_index_from_stash_stmt,
            store_filestore_index_to_stash_stmt;
        SynchronizedFile filestorage;
    public:


        /** @brief Database connector constructor
         * init the databasse connector with the settings that
         * will be used to reach the database
         */
        DBManager();

        /** @brief Destructor for the database connector
         * The destructor for Database connector will just close the file and connections left open
         */
        ~DBManager();

        /** @brief Ensure proper connection to the required schema
         */
        void connect_schema();

        /** @brief Ensure the required schema is present in the DB
         */
        void init_database(const std::string &filename);

        /** @brief Connect to database
         * Actual connection to the database is performed
         * in this method. It can be called to ensure that
         * the connection is running properly
         */
        bool ensure_database_connection();

        /**
         * For the integrated web server it is necessary to have
         * ONLY_FULL_GROUP_BY disabled in mysql. This function will check and 
         * attempt to disable the sql mode
         */
        void check_sql_mode();


        void check_database_connection(){
            if (!ensure_database_connection())
                prepare_queries();
        }

        virtual void prepare_queries(){};

        /** @brief Create a db query starting from a string
         * @param query query string
         * @return DBQuery object which allow to execute the query and fetch results
         */
        std::shared_ptr<DBQuery> prepare_query(const std::string & query);

        void begin_transaction();
        void end_transaction();

        void execute_query(const std::string & stmt);

        void lockTables(int selection=Utils::CERTIFICATE);
        void unlockTables();
        std::string get_certificate_from_filestore(const std::string&, const int, const int);
        std::string get_certificate_from_filestore(const std::string &hash);
        std::shared_ptr<std::istream> get_certificate_stream_from_filestore(const std::string &filename, const int, const int);
        std::tuple<std::string, int> store_certificate_to_filestore(const std::string &);
        bool get_from_cache(const std::string &key, std::string & value);
        void store_in_cache(const std::string &key, const std::string &value);

};
}
}
#endif
