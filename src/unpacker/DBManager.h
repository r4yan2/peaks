#ifndef UNPACKER_DBMANAGER_H
#define UNPACKER_DBMANAGER_H

#include <forward_list>
#include <vector>
#include <Key.h>
#include <common/utils.h>
#include <common/DBManager.h>
#include <common/DBStruct.h>
#include <boost/algorithm/string.hpp>
#include <common/config.h>

using namespace peaks::settings;
using namespace peaks::common;

namespace peaks{
namespace unpacker{

/** @brief Class manging the database
 * Database manager for the unpacked, it will store data in the csv
 * load the csv into the database, and check expired/revoked/invalid
 * keys after all operations
 */
class UNPACKER_DBManager: public DBManager {
public:
    /** @brief Database connector constructor
     * init the databasse connector with the settings that
     * will be used to reach the database
     */
    UNPACKER_DBManager();

    /** @brief Destructor for the database connector
     * The destructor will just close the file left open
     */
    ~UNPACKER_DBManager();

    void prepare_queries();

    /** @brief Recover the certificates to unpack
     * Perform a query on the certificate table to
     * recover the first l certificates to work on
     * @param l number of certificates to retrieve
     * @return certificates data
     */
    std::vector<DBStruct::gpg_keyserver_data> get_certificates(const unsigned long &l);
    std::shared_ptr<DBResult> get_certificates_iterator(const unsigned long &l);
    DBStruct::gpg_keyserver_data get_certificate_from_results(const std::shared_ptr<DBResult> &);
    bool existSignature(const DBStruct::signatures &s);

    /** @brief In case of error mark the certificate not analyzable
     * @param version version of the certificate (primary key)
     * @param fingerprint fingerprint of the certificate (primary key)
     * @param comment reason for the error
     */
    void set_as_not_analyzable(const int &version, const std::string &fingerprint, const std::string &comment);

    /** @brief Updates issuing fingerprint 
     * Update issuing signatures fingerprint in the signatures table
     */
    void UpdateSignatureIssuingFingerprint();

    /** @brief Scan the databsae for expired keys
     */
    void UpdateIsExpired();

    /** @brief Scan the database for revoked keys
     */
    void UpdateIsRevoked();

    /** @brief Scan the database for invalid keys
     */
    void UpdateIsValid();

    void UpdateSignatureIssuingUsername();

private:

    std::shared_ptr<DBQuery>
        get_analyzable_cert_stmt, 
        get_signature_by_index, 
        set_key_not_analyzable,
        insert_error_comments,
        update_issuing_fingerprint,
        update_issuing_username,
        update_expired,
        update_revoked_1,
        update_revoked_2,
        update_valid,
        set_unpacking_status_stmt
           ;

    std::mutex mtx;
};

} //end namespace unpacker
} // end namespace peaks
#endif //UNPACKER_DBMANAGER_H
