#ifndef DBMANAGER_H
#define DBMANAGER_H

#ifdef USE_MYSQL
#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>
#endif
#ifdef USE_MARIADB_C
#include <mariadb/mysql.h>
#include <map>
#endif
#ifdef USE_MARIADB_CPP
#include <mariadb++/statement.hpp>
#include <mariadb++/account.hpp>
#include <mariadb++/connection.hpp>
#include <mariadb++/result_set.hpp>
using namespace mariadb;
#endif

#include <memory>
#include <vector>

struct DBSettings{
    std::string db_user;
    std::string db_password;
    std::string db_host;
    std::string db_database;
};

class DBResult {
    private:
        #ifdef USE_MYSQL
        std::unique_ptr<sql::ResultSet> res;
        #endif
        #ifdef USE_MARIADB
        MYSQL_STMT * stmt;
        MYSQL_BIND * bind_vect;
        std::map<std::string, int> field_map;
        #endif
        #ifdef USE_MARIADB_CPP
        result_set_ref res;
        #endif
    public:
        #ifdef USE_MYSQL
        DBResult(std::unique_ptr<sql::ResultSet> &);
        #endif
        #ifdef USE_MARIADB_C
        DBResult(MYSQL_STMT *);
        #endif
        #ifdef USE_MARIADB_CPP
        DBResult(mariadb::result_set_ref &);
        #endif
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
        #ifdef USE_MYSQL
        std::shared_ptr<sql::PreparedStatement> stmt;
        std::vector<std::istream *> trash_bin;
        #endif

        #ifdef USE_MARIADB_C
        MYSQL_STMT * stmt;
        int param_count;
        unsigned long int max_allowed_packet;
        MYSQL_BIND * bind_vect;
        std::vector<std::pair<int,std::string>> chunks;
        #endif

        #ifdef USE_MARIADB_CPP
        mariadb::statement_ref stmt;
        #endif
    public:

        #ifdef USE_MYSQL
        DBQuery(std::shared_ptr<sql::PreparedStatement> & stmt_);
        #endif

        #ifdef USE_MARIADB
        DBQuery(MYSQL_STMT * stmt_, MYSQL * conn_);
        #endif

        #ifdef USE_MARIADB_CPP
        DBQuery(mariadb::statement_ref & stmt_);
        #endif

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
    private:
        DBSettings settings;

        #ifdef USE_MYSQL
        sql::Driver *driver;
        std::shared_ptr<sql::Connection> con;
        #endif
        #ifdef USE_MARIADB_C
        MYSQL* con;
        #endif
        #ifdef USE_MARIADB_CPP
        mariadb::account_ref acc;
        mariadb::connection_ref con;
        #endif
        
    public:

        DBManager(){};

        /** @brief Database connector constructor
         * init the databasse connector with the settings that
         * will be used to reach the database
         * @param settings_ DBSettings struct containing data for the connection
         */
        DBManager(const DBSettings & settings_);

        /** @brief Destructor for the database connector
         * The destructor for Database connector will just close the file and connections left open
         */
        ~DBManager();

        /** @brief getter for settings
         * @return settings
         */
        DBSettings get_settings() const {return settings;};

        /** @brief Connect to database
         * Actual connection to the database is performed
         * in this method. It can be called to ensure that
         * the connection is running properly
         */
        bool ensure_database_connection();

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
        void execute_query(const std::string & stmt);
};


#endif
