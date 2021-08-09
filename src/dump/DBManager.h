#ifndef DUMP_DBMANAGER_H
#define DUMP_DBMANAGER_H

#include <common/DBManager.h>
#include <vector>

using namespace peaks::common;
namespace peaks{
namespace dump{

typedef std::vector<std::string> query_template;

/** @brief Class manging the database
 * Database manager for the unpacked, it will do the effective data dump into several csv file
 */
class DUMP_DBManager: public DBManager {
    static query_template 
        dump_gpgkeyserver_stmt,
        dump_pubkey_stmt, 
        dump_signature_stmt, 
        dump_self_signature_stmt, 
        dump_userID_stmt,
        dump_userAtt_stmt, 
        dump_unpackerErrors_stmt,
        dump_brokenKey_stmt;

public:
    DUMP_DBManager();
    
    /** @brief Dump content of database into CSV 
     * @param f filename of the csv to create
     * @param table source table
     */
    void dumpCSV(const unsigned int &table);

    /** @brief get dump location
     * @return string
     */

    std::string get_dump_path();

    void set_dump_path(const std::string & dump_path_);

    void write_pubkey_csv();
    void write_userAttributes_csv();
    void write_userID_csv();
    void write_signature_csv();
    void write_self_signature_csv();
    void write_gpg_keyserver_csv();
    void dumplocalCSV(const unsigned int &table);

private:

    std::string dump_path;

};

}
}

#endif //DUMP_DBMANAGER_H
