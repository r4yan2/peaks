#include <boost/filesystem/fstream.hpp>
#include <sys/syslog.h>
#include <cstring>
#include <sstream>
#include <thread>

#include "DBManager.h"
#include "common/DBStruct.h"
#include <boost/program_options.hpp>
#include <common/config.h>

using namespace std;

namespace peaks{
namespace import{
IMPORT_DBManager::IMPORT_DBManager():DBManager()
{
	tables = {
        Utils::TABLES::CERTIFICATE,
    };
    connect_schema();
    prepare_queries();
    Utils::create_folders(CONTEXT.dbsettings.tmp_folder);
    Utils::create_folders(CONTEXT.dbsettings.error_folder);
}

void IMPORT_DBManager::prepare_queries() {
    get_signature_by_index = prepare_query("SELECT id "
                                     "FROM Signatures WHERE r = (?) and s = (?)");
    insert_gpg_keyserver = prepare_query("INSERT INTO gpg_keyserver (version,ID,fingerprint,hash,is_unpacked,error_code,filename,origin,len) VALUES (?,?,?,?,?,?,?,?,?)");
}

IMPORT_DBManager::~IMPORT_DBManager()
{}

bool IMPORT_DBManager::existSignature(const DBStruct::signatures &s){
    std::istream *r_sign = new istringstream(s.rString);
    std::istream *s_sign = new istringstream(s.sString);
    try {
        get_signature_by_index->setBlob(1, r_sign);
        get_signature_by_index->setBlob(2, s_sign);
        std::unique_ptr<DBResult> result = get_signature_by_index->execute();
        return result->next();
    }catch (exception &e){
        syslog(LOG_CRIT, "get_signature_by_index FAILED, there may be a double signature in the database! - %s", e.what());
        return false;
    }
}

void IMPORT_DBManager::drop_index_gpg_keyserver(){
	execute_query("ALTER TABLE gpg_keyserver DROP INDEX id;");
	execute_query("ALTER TABLE gpg_keyserver DROP INDEX fingerprint;");
	execute_query("ALTER TABLE gpg_keyserver DROP INDEX HASH;");
}

void IMPORT_DBManager::build_index_gpg_keyserver(){
	execute_query("ALTER TABLE gpg_keyserver ADD INDEX `id` (`ID`);");
	execute_query("ALTER TABLE gpg_keyserver ADD INDEX `fingerprint` (`fingerprint`, `version`);");
	execute_query("ALTER TABLE gpg_keyserver ADD INDEX `HASH` (`hash` ASC);");
}

void IMPORT_DBManager::write_gpg_keyserver_table(const DBStruct::gpg_keyserver_data &gpg_data){
    try{
        insert_gpg_keyserver->setInt(1, gpg_data.version);
        insert_gpg_keyserver->setString(2, gpg_data.ID);
        insert_gpg_keyserver->setString(3, gpg_data.fingerprint);
        insert_gpg_keyserver->setString(4, gpg_data.hash);
        insert_gpg_keyserver->setInt(5, 0);
        insert_gpg_keyserver->setInt(6, 0);
        insert_gpg_keyserver->setString(7, gpg_data.filename);
        insert_gpg_keyserver->setInt(8, gpg_data.origin);
        insert_gpg_keyserver->setInt(9, gpg_data.len);
        insert_gpg_keyserver->execute();
    }catch (exception &e){
        syslog(LOG_CRIT, "write_gpg_keyserver_csv FAILED, the key will not have the certificate in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_gpg_keyserver_csv(const DBStruct::gpg_keyserver_data &gpg_data){
    try{
        ostringstream f;
        f << '"' << to_string(gpg_data.version) << "\",";
        f << '"' << gpg_data.ID << "\",";
        f << '"' << hexlify(gpg_data.fingerprint) << "\",";
        f << '"' << gpg_data.hash << "\",";
        f << '"' << gpg_data.is_unpacked << "\",";
        f << '"' << to_string(gpg_data.error_code) << "\",";
        f << '"' << gpg_data.filename << "\",";
        f << '"' << to_string(gpg_data.origin) << "\",";
        f << '"' << to_string(gpg_data.len) << "\",";
        f << "\n";
		file_list.at(Utils::CERTIFICATE)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_gpg_keyserver_csv FAILED, the key will not have the certificate in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_pubkey_csv(const DBStruct::pubkey &pubkey) {
    try{
        ostringstream f;
        f << '"' << pubkey.keyId << "\",";
        f << '"' << pubkey.version << "\",";
        f << '"' << hexlify(pubkey.fingerprint) << "\",";
        f << '"' << hexlify(pubkey.priFingerprint) << "\",";
        f << '"' << pubkey.pubAlgorithm << "\",";
        f << '"' << pubkey.creationTime << "\",";
        f << '"' << pubkey.expirationTime << "\",";
        for (const auto &v: pubkey.algValue){
            f << '"' << hexlify(v) << "\",";
        }
        f << '"' << pubkey.curve<< "\",";
        f << "\n";
		file_list.at(Utils::PUBKEY)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_pubkey_csv FAILED, the key not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_userID_csv(const DBStruct::userID &uid) {
    try{
        ostringstream f;
        f << '"' << uid.ownerkeyID << "\",";
        f << '"' << hexlify(uid.fingerprint) << "\",";
        f << '"' << uid.name << "\",";
        f << "\n";
		file_list.at(Utils::USERID)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userID_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_userAttributes_csv(const DBStruct::userAtt &ua) {
    try{
        ostringstream f;
        f << '"' << to_string(ua.id) << "\",";
        f << '"' << hexlify(ua.fingerprint) << "\",";
        f << '"' << ua.name << "\",";
        f << '"' << ua.encoding << "\",";
        f << '"' << hexlify(ua.image) << "\",";
        f << "\n";
		file_list.at(Utils::USER_ATTRIBUTES)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_userAttributes_csv FAILED, the UserID not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_signature_csv(const DBStruct::signatures &ss) {
    try{
        ostringstream f;
        f << '.' << '"' << ss.type << "\",";
        f << '"' << ss.pubAlgorithm << "\",";
        f << '"' << ss.hashAlgorithm << "\",";
        f << '"' << ss.version << "\",";
        f << '"' << ss.issuingKeyId << "\",";
        f << '"' << ss.signedKeyId << "\",";
        f << '"' << hexlify(ss.issuingFingerprint) << "\",";
        f << '"' << hexlify(ss.signedFingerprint) << "\",";
        f << '"' << ss.signedUsername << "\",";
        f << '"' << ss.issuingUsername << "\",";
        f << '"' << ss.uatt_id << "\",";
        f << '"' << ss.regex << "\",";
        f << '"' << ss.creationTime << "\",";
        f << '"' << ss.expirationTime << "\",";
        f << '"' << hexlify(ss.rString) << "\",";
        f << '"' << hexlify(ss.sString) << "\",";
        f << '"' << hexlify(ss.flags) << "\",";
        f << '"' << hexlify(ss.hashHeader) << "\",";
        f << '"' << hexlify(ss.signedHash) << "\",";
        f << '"' << ss.hashMismatch << "\",";
        f << '"' << ss.keyExpirationTime << "\",";
        f << '"' << ss.revocationCode << "\",";
        f << '"' << ss.revocationReason << "\",";
        f << '"' << ss.revocationSigId << "\",";
        f << '"' << ss.isRevocable << "\",";
        f << '"' << ss.isExportable << "\",";
        f << '"' << ss.isExpired << "\",";
        f << '"' << ss.isRevocation << "\",";
        f << "\n";
		file_list.at(Utils::SIGNATURE)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_self_signature_csv(const DBStruct::signatures &ss) {
    try{
        ostringstream f;
        f << '.' << '"' << ss.type << "\",";
        f << '"' << ss.pubAlgorithm << "\",";
        f << '"' << ss.hashAlgorithm << "\",";
        f << '"' << ss.version << "\",";
        f << '"' << ss.issuingKeyId << "\",";
        f << '"' << hexlify(ss.issuingFingerprint) << "\",";
        f << '"' << hexlify(ss.preferedHash) << "\",";
        f << '"' << hexlify(ss.preferedCompression) << "\",";
        f << '"' << hexlify(ss.preferedSymmetric) << "\",";
        f << '"' << ss.trustLevel << "\",";
        f << '"' << ss.keyExpirationTime << "\",";
        f << '"' << ss.isPrimaryUserId << "\",";
        f << '"' << ss.signedUsername << "\",";
        f << "\n";
		file_list.at(Utils::SELF_SIGNATURE)->write(f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_self_signature_csv FAILED, the signature not have the results of the unpacking in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::write_unpackerErrors_csv(const DBStruct::Unpacker_errors &mod){
    try{
		for (const auto &c: mod.comments){
        	ostringstream f;
            f << '.' << '"' << mod.version << "\",";
            f << '"' << hexlify(mod.fingerprint) << "\"";
            f << '"' << c << "\",";
            f << "\n";
			file_list.at(Utils::UNPACKER_ERRORS)->write(f.str());
        }
    }catch (exception &e){
        syslog(LOG_CRIT, "write_unpackerErrors_csv FAILED, the error of the unpacking will not be in the database! - %s", e.what());
    }
}

void IMPORT_DBManager::UpdateSignatureIssuingUsername() {
    try{
        execute_query("COMMIT");
        execute_query("UPDATE Signatures SET issuingUsername = name WHERE issuingUsername IS NULL AND issuingFingerprint = 1;");
    }catch (exception &e){
        syslog(LOG_CRIT, "update_signature_issuing_fingerprint_stmt FAILED, the issuingFingerprint of the signature will not be inserted! - %s",
                          e.what());
    }
}

}
}
