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
    bool existSignature(const DBStruct::signatures &s);

    /** @brief fill up the Pubkey csv
     * @param pubkey new data to add
     */
    void write_pubkey_csv(const DBStruct::pubkey &pubkey);
    /** @brief fill up the UserID csv
     * @param uid new data to add
     */
    void write_userID_csv(const DBStruct::userID &uid);
    /** @brief fill up the userAttributes csv
     * @param userAtt new data to add
     */
    void write_userAttributes_csv(const DBStruct::userAtt &ua);
    /** @brief fill up the Signature csv
     * @param ss new data to add
     */
    void write_signature_csv(const DBStruct::signatures &ss);
    /** @brief fill up the SelfSignatures csv
     * @param ss new data to add
     */
    void write_self_signature_csv(const DBStruct::signatures &ss);
    /** @brief fill up the UnpackerErrors csv
     * @param mod new data to add
     */
    void write_unpackerErrors_csv(const DBStruct::Unpacker_errors &mod);
    /** @brief fill the Unpacked csv
     * Will be used to change the status of the is_unpacked flag
     * in the certificates table
     * @param key certificate for which change the unpacked value
     * @param mod information about the unpacking status
     */
    void write_unpacked_csv(const OpenPGP::Key::Ptr &key, const DBStruct::Unpacker_errors &mod);

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

    DBSettings settings;

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
        commit,
        set_unpacking_status_stmt;

};


}
}
#endif //UNPACKER_DBMANAGER_H
