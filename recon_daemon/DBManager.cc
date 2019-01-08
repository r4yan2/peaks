#include <sys/syslog.h>
#include <cstring>
#include <sstream>
#include <Misc/mpi.h>
#include <thread>

#include "DBManager.h"

using namespace sql;
using namespace std;
// Database connector initialization
RECON_DBManager::RECON_DBManager(Recon_DBConfig dbsettings) {
    settings = dbsettings;
    RECON_DBManager::driver = get_driver_instance();
    RECON_DBManager::con = shared_ptr<Connection>(driver->connect(settings.db_host, settings.db_user, settings.db_password));
    // Connect to the MySQL keys database
    con->setSchema(settings.db_database);

    // Create prepared Statements
    
    get_pnode_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT * FROM ptree WHERE node_key = (?)"));

    insert_pnode_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("INSERT INTO ptree VALUES (?,?,?,?,?)"));

    update_pnode_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("UPDATE ptree SET node_svalues = (?), num_elements = (?), leaf = (?), node_elements = (?) WHERE node_key = (?)"));
                                      
    delete_pnode_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("DELETE FROM ptree WHERE node_key = (?)"));

    get_all_hash_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT hash FROM gpg_keyserver order by hash ASC"));

    check_key_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("SELECT * FROM gpg_keyserver where hash = (?)"));

	insert_ptree_stmt = make_pair<string, string>(
            "LOAD DATA LOCAL INFILE '", "' IGNORE INTO TABLE ptree FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
            "LINES STARTING BY '.' TERMINATED BY '\\n' (node_key, node_svalues, num_elements, leaf, node_elements) "
            );

	get_removed_hash_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("select * from removed_hash"));

	truncate_removed_hash_stmt = shared_ptr<PreparedStatement>(con->prepareStatement("truncate removed_hash"));

}

RECON_DBManager::~RECON_DBManager(){
    driver->threadEnd();
};

void RECON_DBManager::lockTables(){
    try{
        shared_ptr<Statement>(con->createStatement())->execute("LOCK TABLES ptree WRITE;");
    }catch (exception &e){
        syslog(LOG_WARNING, "lock_tables_stmt FAILED, the query will be slowly! - %s", e.what());
    }
}

void RECON_DBManager::unlockTables(){
    try{
        shared_ptr<Statement>(con->createStatement())->execute(("UNLOCK TABLES;"));
    }catch (exception &e){
        syslog(LOG_CRIT, "unlock_tables_stmt FAILED, the tables will remain locked! - %s", e.what());
    }
}

void RECON_DBManager::insert_node(const RECON_DBStruct::node &n){
  try{
    insert_pnode_stmt->setString(1, n.key);
    insert_pnode_stmt->setString(2, n.svalues);
    insert_pnode_stmt->setInt(3, n.num_elements);
    insert_pnode_stmt->setBoolean(4, n.leaf);
    insert_pnode_stmt->setString(5, n.elements);
    insert_pnode_stmt->executeQuery();
  }
  catch (SQLException &e){
    if(e.getErrorCode() == 1062){
      syslog(LOG_INFO, "inserting pnode failed - node already present %s", e.what());
    }else{
      syslog(LOG_ERR, "inserting pnode failed - %s", e.what());
    }
    }
  }
  
void RECON_DBManager::update_node(const RECON_DBStruct::node &n){
  try{
    update_pnode_stmt->setString(1, n.svalues);
    update_pnode_stmt->setInt(2, n.num_elements);
    update_pnode_stmt->setBoolean(3, n.leaf);
    update_pnode_stmt->setString(4, n.elements);
    update_pnode_stmt->setString(5, n.key);
    update_pnode_stmt->executeQuery();
  }
  catch (SQLException &e){
    if(e.getErrorCode() == 1062){
      syslog(LOG_INFO, "update pnode failed %s", e.what());
    }else{
      syslog(LOG_ERR, "update pnode failed - %s", e.what());
    }
    }
}

RECON_DBStruct::node RECON_DBManager::get_node(const std::string k){
  RECON_DBStruct::node n;
  get_pnode_stmt->setString(1, k);
  result = shared_ptr<ResultSet>(get_pnode_stmt->executeQuery());
  result->next();
  n = {k, result->getString("node_svalues"), result->getInt("num_elements"), result->getBoolean("leaf"), result->getString("node_elements")};
  return n;
  }

std::vector<std::string> RECON_DBManager::get_all_hash(){
    std::vector<std::string> hashes;
    result = shared_ptr<ResultSet>(get_all_hash_stmt->executeQuery());
    while(result->next()){
        std::string hash = result->getString("hash");
        hashes.push_back(hash);
    }
    return hashes;
}

void RECON_DBManager::delete_node(const std::string k){
  try{
    delete_pnode_stmt->setString(1,k);
    delete_pnode_stmt->executeQuery();
  } catch (exception &e){
    syslog(LOG_WARNING, "Hash not found: %s", k.c_str());
  }
}

bool RECON_DBManager::check_key(const std::string k){
    try{
        check_key_stmt->setString(1,k);
        result = shared_ptr<ResultSet>(check_key_stmt->executeQuery());
        result->next();
		result->getString("hash");
        //std::cout << k << "-> OK - " << result->getString("hash") << std::endl;
    } catch (exception &e){
        //std::cout << k << "-> KO" << std::endl;
        return false;
    }
    return true;
}

void RECON_DBManager::write_ptree_csv(const RECON_DBStruct::node &pnode) {
    try{
        csv_file << '.';
		csv_file << '"' << pnode.key << "\",";
        csv_file << '"' << pnode.svalues << "\",";
        csv_file << '"' << pnode.num_elements << "\",";
        csv_file << '"' << pnode.leaf << "\",";
        csv_file << '"' << pnode.elements << "\",";
        csv_file << "\n";
    }catch (exception &e){
        syslog(LOG_CRIT, "write_ptree_csv FAILED, the node will not be in the database! - %s", e.what());
    }
}

void RECON_DBManager::openCSVFiles(){
    // Open file
    csv_file = ofstream(settings.tmp_folder + "ptree.csv");
}

void RECON_DBManager::insertCSV(){
	try{
    	shared_ptr<Statement>(con->createStatement())->execute(insert_ptree_stmt.first + settings.tmp_folder + "ptree.csv" + insert_ptree_stmt.second);
    }catch (exception &e){
        syslog(LOG_CRIT, "insert_ptree_stmt FAILED, the key will not have the ptree in the database! - %s", e.what());
	}
}

std::vector<std::string> RECON_DBManager::fetch_removed_elements(){
    std::vector<std::string> hashes;
    result = shared_ptr<ResultSet>(get_removed_hash_stmt->executeQuery());
    while(result->next()){
        std::string hash = result->getString("hash");
        hashes.push_back(hash);
    }
	truncate_removed_hash_stmt->executeQuery();
    return hashes;
}

void RECON_DBManager::closeCSVFiles(){
    csv_file.close();
}
