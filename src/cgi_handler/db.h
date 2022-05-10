#ifndef PEAKS_DB_H_
#define PEAKS_DB_H_

#include <forward_list>
#include <vector>
#include <common/DBStruct.h>
#include "db_key.h"
#include <common/DBManager.h>
#include <set>
#include <common/utils.h>

typedef std::tuple<int, bool, int, int> certificate_data_t;
typedef std::tuple<int, bool> userattribute_data_t;
typedef std::tuple<int, int, int, int, int, std::string, int> pubkey_data_t;
typedef std::tuple<int, int, int, int, int, int> signature_data_t;
typedef std::tuple<int, std::string> userid_data_t;
using namespace peaks::common;
using namespace peaks::common::DBStruct;
using namespace peaks::common::Utils;
namespace peaks {
namespace pks{

const int SUCCESS = 0;
const int ERROR = -1;
const int KEY_NOT_FOUND = -2;

class CGI_DBManager: public DBManager {
public:
    /**
     * default constructor
     */
    CGI_DBManager();
    /**
     * default destructor
     */
    ~CGI_DBManager();

	/**
	 * prepare some queries
	 */
	void prepare_queries();

	/**
	 * search functionality based on key length
	 * 8 -> shortIDQuery
	 * 16 -> longIDQuery
	 * 32 -> Fingerprint Query (v3)
	 * 40 -> Fingerprint Query (v4)
	 * @param key query string
	 * @return success status
	 */
    int searchKey(std::string key, std::string & result);

	/**
	 * Query the database searching for certificates with id
	 * ending in <keyID>
	 * @param keyID id to search
	 * @return certificate blob (stream)
	 */
	std::string shortIDQuery(const std::string &keyID);

	/**
	 * Query the database searching for certificates with id
	 * equal to <keyID>
	 * @param keyID id to search
	 * @return certificate blob (stream)
	 */
	std::string longIDQuery(const std::string &keyID);
	/**
	 * Query the database searching for certificates with
	 * fingerprint equal to <fp>
	 * @param fp fingerprint to search
	 * @return certificate blob
	 */
	std::string fingerprintQuery(const std::string &fp);

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
    void insert_user_id(const userID &uid);

	/** 
	 * Verbose index query entrypoint
	 * @param id Key ID to search
	 * @return key material if found
	 */
    full_key vindexQuery(std::string id);

    void insert_broken_key(const std::string &cert, const std::string &comment);

    std::string get_key_by_hash(const std::string &hash);
    std::vector<int> get_certificates_with_attributes();
    std::vector<DBStruct::userAtt> get_user_attributes();

    /**
     * Recover nodes information
     * from the prefix tree table 
     * @return vector containing nodes information
     */
    std::vector<node> get_pnodes();
    std::vector<certificate_data_t> get_certificates_analysis();
    std::tuple<int, int, int> get_certificates_generic_stats();
    std::vector<std::tuple<int, int>> get_certificates_unpacking_status();
    std::vector<userattribute_data_t> get_user_attributes_data();
    std::vector<pubkey_data_t> get_pubkey_data(const int &min_year, const int &max_year);
    std::vector<signature_data_t> get_signature_data();
    std::vector<userid_data_t> get_userid_data();

private:
	std::shared_ptr<DBQuery>
			shortid_stmt, 
			longid_stmt, 
			fprint_stmt, 
			index_stmt, 
			insert_gpg_stmt,
            update_gpg_stmt, 
			insert_uid_stmt, 
			insert_brokenKey_stmt, 
			vindex_prikey_full_id_stmt, 
			vindex_prikey_short_id_stmt,
            vindex_prikey_fp_stmt, 
			vindex_uid_fp_stmt, 
			vindex_signatures_stmt, 
			vindex_uatt_stmt,
            vindex_subkey_fp_stmt, 
			vindex_key_vuln_stmt, 
			vindex_sign_vuln_stmt, 
			get_by_hash_stmt,
      get_pnodes_stmt,
      get_certificates_with_attributes_stmt,
      get_from_cache_stmt,
      store_in_cache_stmt,
      get_certificates_analysis_stmt,
      get_certificates_unpacking_status_stmt,
      get_certificates_generic_stats_stmt,
      get_user_attributes_data_stmt,
      get_pubkey_data_stmt,
      get_signature_data_stmt,
      get_userid_data_stmt;
    
	std::string hexToUll(const std::string &hex) {
        unsigned long long ullKey = std::stoull(hex, nullptr, 16);
        return std::to_string(ullKey);
    }


    key get_key_info(const std::unique_ptr<DBResult> & key_result);

    std::forward_list<signature> get_signatures(const std::string &signedFingerprint, const std::string &signedUsername = "", const int &ua_id = -1);

    std::forward_list<uid> get_users(const std::string &id);

    std::forward_list<ua> get_userAtt(const uid &tmp_uid);

    std::forward_list<std::string> get_key_vuln(const unsigned int &version, const std::string &fingerprint);

    std::forward_list<std::string> get_sign_vuln(const unsigned int &sign_id);
};

} // namespace peaks

}
#endif // PEAKS_DB_H_
