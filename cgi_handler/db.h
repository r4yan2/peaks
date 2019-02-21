#ifndef PEAKS_DB_H_
#define PEAKS_DB_H_

#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/driver.h>
#include <forward_list>
#include <vector>
#include "db_key.h"
#include "utils.h"
#include "Config.h"

namespace peaks {

const int SUCCESS = 0;
const int ERROR = -1;
const int KEY_NOT_FOUND = -2;

struct gpg_keyserver_data{
    int version;
    std::string ID;
    std::string fingerprint;
    std::string certificate;
    int error_code;
    std::string hash;
};

struct userID_data{
    std::string ownerkeyID;
    std::string fingerprint;
    std::string name;
    std::string email;
};

class DBManager {
public:
    DBManager(const Cgi_DBConfig &db_settings);
    ~DBManager();
	void ensure_connection();
    int searchKey(std::string key, std::istream*& result);
    std::istream* shortIDQuery(const std::string &keyID);
    std::istream* longIDQuery(const std::string &keyID);
    std::istream* fingerprintQuery(const std::string &fp);
    std::forward_list<DB_Key*> *indexQuery(std::string key);
    void update_gpg_keyserver(const gpg_keyserver_data &gk);
    void insert_gpg_keyserver(const gpg_keyserver_data &gk);
    void insert_user_id(const userID_data &uid);
    peaks::full_key vindexQuery(std::string id);

    void insert_broken_key(const std::string &cert, const std::string &comment);

    std::string get_key_by_hash(const std::string &hash);

private:
	Cgi_DBConfig settings;
    sql::Driver *driver;
    std::shared_ptr<sql::Connection> con;
    std::shared_ptr<sql::PreparedStatement> shortid_stmt, longid_stmt, fprint_stmt, index_stmt, insert_gpg_stmt,
            update_gpg_stmt, insert_uid_stmt, insert_brokenKey_stmt, vindex_prikey_id_stmt,
            vindex_prikey_fp_stmt, vindex_uid_fp_stmt, vindex_signatures_stmt, vindex_uatt_stmt,
            vindex_subkey_fp_stmt, vindex_key_vuln_stmt, vindex_sign_vuln_stmt, get_by_hash_stmt;
    std::shared_ptr<sql::ResultSet> result;
    std::string hexToUll(const std::string &hex) {
        unsigned long long ullKey = std::stoull(hex, nullptr, 16);
        return std::to_string(ullKey);
    }


    key get_key_info(const std::shared_ptr<sql::ResultSet> &key_result);

    std::forward_list<signature> get_signatures(const std::string &signedFingerprint, const std::string &signedUsername = "", const int &ua_id = -1);

    std::forward_list<uid> get_users(const std::string &id);

    std::forward_list<ua> get_userAtt(const uid &tmp_uid);

    std::forward_list<std::string> get_key_vuln(const unsigned int &version, const std::string &fingerprint);

    std::forward_list<std::string> get_sign_vuln(const unsigned int &sign_id);
};

} // namespace peaks

#endif // PEAKS_DB_H_
