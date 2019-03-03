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
#include <boost/algorithm/string.hpp>

namespace peaks {

const int SUCCESS = 0;
const int ERROR = -1;
const int KEY_NOT_FOUND = -2;


/**
 * helper struct to store the values coming from the database
 */
struct gpg_keyserver_data{
    int version;
    std::string ID;
    std::string fingerprint;
    std::string certificate;
    int error_code;
    std::string hash;
};

/**
 * helper struct to store the values coming from the database
 */
struct userID_data{
    std::string ownerkeyID;
    std::string fingerprint;
    std::string name;
    std::string email;
};

class DBManager {
public:
    DBManager(const Cgi_DBConfig &db_settings);
    /**
     * default destructor
     */
    ~DBManager();

	/**
	 * ensure that the database connection is up
	 * and is case is down restart it
	 */
	void ensure_connection();

	/**
	 * search functionality based on key length
	 * 8 -> shortIDQuery
	 * 16 -> longIDQuery
	 * 32 -> Fingerprint Query (v3)
	 * 40 -> Fingerprint Query (v4)
	 * @param key query string
	 * @param result pointer in which store the final result
	 * @return success status
	 */
    int searchKey(std::string key, std::istream*& result);

	/**
	 * Query the database searching for certificates with id
	 * ending in <keyID>
	 * @param keyID id to search
	 * @return std::istream* pointer to the certificate blob
	 */
    std::istream* shortIDQuery(const std::string &keyID);

	/**
	 * Query the database searching for certificates with id
	 * equal to <keyID>
	 * @param keyID id to search
	 * @return std::istream* pointer to the certificate blob
	 */
    std::istream* longIDQuery(const std::string &keyID);
	/**
	 * Query the database searching for certificates with
	 * fingerprint equal to <fp>
	 * @param fp fingerprint to search
	 * @return std::istream* pointer to the certificate blob
	 */
    std::istream* fingerprintQuery(const std::string &fp);

	/**
	 * normal index query entrypoint
	 * @param key query string
	 * @return list of keys found
	 */
    std::forward_list<DB_Key*> *indexQuery(std::string key);

	/**
	 * Updating certificate table in the database
	 * with the content of the updated certificate
	 * @param gk new certificate data
	 */
    void update_gpg_keyserver(const gpg_keyserver_data &gk);
	/**
	 * Insert into the certificate table in the database
	 * the content of the new certificate
	 * @param gk new certificate data
	 */
    void insert_gpg_keyserver(const gpg_keyserver_data &gk);
	/**
	 * Updating UserID table in the database
	 * with the new userID data
	 * @param uid new data
	 */
    void insert_user_id(const userID_data &uid);

	/** 
	 * Verbose index query entrypoint
	 * @param id Key ID to search
	 * @return key material if found
	 */
    peaks::full_key vindexQuery(std::string id);

    void insert_broken_key(const std::string &cert, const std::string &comment);

    std::string get_key_by_hash(const std::string &hash);

private:
	Cgi_DBConfig settings;
    sql::Driver *driver;
    std::shared_ptr<sql::Connection> con;
    std::shared_ptr<sql::PreparedStatement> shortid_stmt, longid_stmt, fprint_stmt, index_stmt, insert_gpg_stmt,
            update_gpg_stmt, insert_uid_stmt, insert_brokenKey_stmt, vindex_prikey_full_id_stmt, vindex_prikey_short_id_stmt,
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
