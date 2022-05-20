#ifndef DBMANAGER_H
#define DBMANAGER_H

#include <cppconn/connection.h>
#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>

#include <ios>
#include <memory>
#include <vector>
#include <string>

#include <common/utils.h>
#include "DBStruct.h"

namespace peaks{
namespace common{

class DBResult {
    private:
        sql::ResultSet * res;
    public:
        DBResult(sql::ResultSet *);
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

struct DataBuf : public std::streambuf
{
    DataBuf(char* s, std::size_t n)
    {
        setg(s, s, s + n);
    }
};

class DBQuery {
    private:
        std::string query;
        std::shared_ptr<sql::PreparedStatement> stmt;
        std::vector<std::istream *> trash_bin;
        std::vector<DataBuf *> trash_bin_2;
        std::map<int, std::string> params;
        int pos;

    public:

        DBQuery(sql::Connection * con, const std::string & stmt_);
        ~DBQuery();

        void refresh(sql::Connection * con);
        std::unique_ptr<DBResult> execute();
        void setBlob(int, const std::string &);
        void setBlob(int, std::istream *);
        void setBoolean(int, const bool);
        void setString(int, const std::string &);
        void setBigInt(int, const std::string &);
        void setInt(int, int);
};

class DBManager {
    protected:
        std::vector<unsigned int> tables;
        std::map<unsigned int, unsigned int> file_list;
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
        unsigned int filestorage_handler;
    static std::pair<std::string, std::string> 
        insert_certificate_stmt, 
        insert_brokenKey_stmt, 
        insert_pubkey_stmt, 
        insert_signature_stmt, 
        insert_self_signature_stmt, 
        insert_userID_stmt,
        insert_userAtt_stmt, 
        insert_unpackerErrors_stmt, 
        insert_unpacked_stmt;

    static std::string 
        create_unpacker_tmp_table,
        update_gpg_keyserver,
        drop_unpacker_tmp_table;

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
        void rollback_transaction();
        void end_transaction();

        void execute_query(const std::string & stmt);

        void lockTables();
        void unlockTables();
        std::string get_certificate_from_filestore(const std::string&, const int, const int);
        std::string get_certificate_from_filestore(const std::string &hash);
        std::shared_ptr<std::istream> get_certificate_stream_from_filestore(const std::string &filename, const int);
        std::tuple<std::string, int> store_certificate_to_filestore(const std::string &);
        int get_from_cache(const std::string &key, std::string & value);
        void store_in_cache(const std::string &key, const std::string &value);
        
        /** @brief Bulk-insert CSV into the database
         * Insert multiple csv into the respective table 
         * of the database via LOAD DATA INFILE operation
         */
        void insertCSV(bool lock=false);
        void insertCSV(const std::string &f, const unsigned int &t);

        /** @brief Ready CSV files for writing tmp data
         */
        void openCSVFiles();
        void flushCSVFiles();
        void closeCSVFiles();

};
}
}
#endif
