#ifndef DBMANAGER_H
#define DBMANAGER_H

#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>

#include <memory>
#include <vector>
#include <string>

#include <common/utils.h>

namespace peaks{
namespace common{

struct DBSettings{
    std::string db_user;
    std::string db_password;
    std::string db_host;
    std::string db_database;
    std::string tmp_folder;
    std::string error_folder;
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
        DBSettings settings;
        std::map<int, std::string> tables;
    private:
        sql::Driver *driver;
        std::shared_ptr<sql::Connection> con;
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

        void lockTables(int selection=Utils::CERTIFICATE);
        void unlockTables();

};
}
}
#endif
