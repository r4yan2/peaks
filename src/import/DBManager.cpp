#include <boost/filesystem/fstream.hpp>
#include <sys/syslog.h>
#include <cstring>
#include <sstream>
#include <thread>

#include "DBManager.h"
#include "common/DBStruct.h"
#include <boost/program_options.hpp>
#include <common/config.h>
#include <common/FileManager.h>

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
		FILEMANAGER.write(file_list.at(Utils::CERTIFICATE), f.str());
    }catch (exception &e){
        syslog(LOG_CRIT, "write_gpg_keyserver_csv FAILED, the key will not have the certificate in the database! - %s", e.what());
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
			FILEMANAGER.write(file_list.at(Utils::UNPACKER_ERRORS), f.str());
        }
    }catch (exception &e){
        syslog(LOG_CRIT, "write_unpackerErrors_csv FAILED, the error of the unpacking will not be in the database! - %s", e.what());
    }
}


}
}
