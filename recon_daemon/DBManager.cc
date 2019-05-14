#include <sys/syslog.h>
#include <cstring>
#include <sstream>
#include <Misc/mpi.h>
#include <thread>

#include "DBManager.h"

using namespace std;
// Database connector initialization

RECON_DBManager::RECON_DBManager( const DBSettings & db_settings, const std::string & tmp_folder_ ): DBManager(db_settings){
    tmp_folder = tmp_folder_;
}

std::vector<std::string> Recon_memory_DBManager::fetch_removed_elements(){
    throw std::runtime_error("Cannot fetch removed elements from memory database manager");
}


std::vector<std::string> Recon_mysql_DBManager::get_all_hash(){
    throw std::runtime_error("Useless to fetch hashes from the database in mysql database manager");
};

void Recon_mysql_DBManager::commit_memtree(){
    throw std::runtime_error("Cannot commit whole tree in mysql database manager");
};

Recon_mysql_DBManager::Recon_mysql_DBManager(const DBSettings & dbsettings, const std::string & tmp_folder_): RECON_DBManager(dbsettings, tmp_folder_) {
    prepare_queries();
}

void Recon_mysql_DBManager::prepare_queries(){
    
    get_pnode_stmt = prepare_query("SELECT * FROM ptree WHERE node_key = (?)");

    insert_pnode_stmt = prepare_query("INSERT INTO ptree VALUES (?,?,?,?,?)");

    update_pnode_stmt = prepare_query("UPDATE ptree SET node_svalues = (?), num_elements = (?), leaf = (?), node_elements = (?) WHERE node_key = (?)");
                                      
    delete_pnode_stmt = prepare_query("DELETE FROM ptree WHERE node_key = (?)");

    check_key_stmt = prepare_query("SELECT * FROM gpg_keyserver where hash = (?)");

	insert_ptree_stmt = make_pair<string, string>(
            "LOAD DATA LOCAL INFILE '", "' IGNORE INTO TABLE ptree FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
            "LINES STARTING BY '.' TERMINATED BY '\\n' (node_key, node_svalues, num_elements, leaf, node_elements) "
            );

	get_removed_hash_stmt = prepare_query("select hash from removed_hash");

	truncate_removed_hash_stmt = prepare_query("truncate removed_hash");

}

void Recon_mysql_DBManager::insert_node(const RECON_DBStruct::node &n){
  try{
    insert_pnode_stmt->setString(1, n.key);
    insert_pnode_stmt->setString(2, n.svalues);
    insert_pnode_stmt->setInt(3, n.num_elements);
    insert_pnode_stmt->setBoolean(4, n.leaf);
    insert_pnode_stmt->setString(5, n.elements);
    insert_pnode_stmt->execute();
  }
  catch (std::exception &e){
      syslog(LOG_ERR, "inserting pnode failed - %s", e.what());
    }
  }
  
void Recon_mysql_DBManager::update_node(const RECON_DBStruct::node &n){
  try{
    update_pnode_stmt->setString(1, n.svalues);
    update_pnode_stmt->setInt(2, n.num_elements);
    update_pnode_stmt->setBoolean(3, n.leaf);
    update_pnode_stmt->setString(4, n.elements);
    update_pnode_stmt->setString(5, n.key);
    update_pnode_stmt->execute();
  }
  catch (std::exception &e){
      syslog(LOG_ERR, "update pnode failed - %s", e.what());
    }
}

RECON_DBStruct::node Recon_mysql_DBManager::get_node(const std::string k){
  RECON_DBStruct::node n;
  get_pnode_stmt->setString(1, k);
  std::unique_ptr<DBResult> result = get_pnode_stmt->execute();
  result->next();
  n = {k, result->getString("node_svalues"), result->getInt("num_elements"), result->getBoolean("leaf"), result->getString("node_elements")};
  return n;
  }

void Recon_mysql_DBManager::delete_node(const std::string k){
  try{
    delete_pnode_stmt->setString(1,k);
    delete_pnode_stmt->execute();
  } catch (exception &e){
    syslog(LOG_WARNING, "Hash not found: %s", k.c_str());
  }
}

bool Recon_mysql_DBManager::check_key(const std::string k){
    try{
        check_key_stmt->setString(1,k);
        std::unique_ptr<DBResult> result = check_key_stmt->execute();
        result->next();
		result->getString("hash");
    } catch (exception &e){
        return false;
    }
    return true;
}

std::vector<std::string> Recon_mysql_DBManager::fetch_removed_elements(){
    std::vector<std::string> hashes;
    std::unique_ptr<DBResult> result = get_removed_hash_stmt->execute();
    while(result->next()){
        std::string hash = result->getString("hash");
        hashes.push_back(hash);
    }
	truncate_removed_hash_stmt->execute();
    return hashes;
}

Recon_memory_DBManager::Recon_memory_DBManager(const DBSettings & dbsettings, const std::string & tmp_folder_) : RECON_DBManager(dbsettings, tmp_folder_){
    prepare_queries();
}

void Recon_memory_DBManager::prepare_queries(){

    get_all_hash_stmt = prepare_query("SELECT hash FROM gpg_keyserver order by hash ASC");

    check_key_stmt = prepare_query("SELECT * FROM gpg_keyserver where hash = (?)");

	insert_ptree_stmt = make_pair<string, string>(
            "LOAD DATA LOCAL INFILE '", "' IGNORE INTO TABLE ptree FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
            "LINES STARTING BY '.' TERMINATED BY '\\n' (node_key, node_svalues, num_elements, leaf, node_elements) "
            );

}

void Recon_memory_DBManager::lockTables(){
    try{
        execute_query("LOCK TABLES ptree WRITE;");
    }catch (exception &e){
        syslog(LOG_WARNING, "lock_tables_stmt FAILED, the query will be slowly! - %s", e.what());
    }
}

void Recon_memory_DBManager::unlockTables(){
    try{
        execute_query("UNLOCK TABLES;");
    }catch (exception &e){
        syslog(LOG_CRIT, "unlock_tables_stmt FAILED, the tables will remain locked! - %s", e.what());
    }
}

void Recon_memory_DBManager::insert_node(const RECON_DBStruct::node &n){
    syslog(LOG_DEBUG, "inserting node %s into memory DB", n.key.c_str());
    memory_storage.insert( std::make_pair(n.key, std::make_tuple(n.svalues, n.num_elements, n.leaf, n.elements)) );
  }
  
void Recon_memory_DBManager::update_node(const RECON_DBStruct::node &n){
    try{
        memory_storage.at(n.key) = std::make_tuple(n.svalues, n.num_elements, n.leaf, n.elements);
    }catch(std::exception &e){
      throw std::runtime_error("update pnode failed");
    }
}

RECON_DBStruct::node Recon_memory_DBManager::get_node(const std::string k){
    RECON_DBStruct::node n;
    n.key = k;
    try{
        std::tie(n.svalues, n.num_elements, n.leaf, n.elements) = memory_storage.at(k);
    }catch(std::exception &e){
        syslog(LOG_WARNING, "DBManager memory error %s", e.what());
        throw std::runtime_error("get pnode failed");
    }
  return n;
  }

std::vector<std::string> Recon_memory_DBManager::get_all_hash(){
    std::vector<std::string> hashes;
    std::unique_ptr<DBResult> result = get_all_hash_stmt->execute();
    while(result->next()){
        std::string hash = result->getString("hash");
        hashes.push_back(hash);
    }
    return hashes;
}

void Recon_memory_DBManager::delete_node(const std::string k){
    syslog(LOG_DEBUG, "deleting node %s from memory DB", k.c_str());
  try{
        memory_storage.erase(k);
  } catch (exception &e){
      throw std::runtime_error("delete pnode failed");
  }
}

bool Recon_memory_DBManager::check_key(const std::string k){
    try{
        check_key_stmt->setString(1,k);
        std::unique_ptr<DBResult> result = check_key_stmt->execute();
        result->next();
		result->getString("hash");
    } catch (exception &e){
        return false;
    }
    return true;
}

void Recon_memory_DBManager::commit_memtree(){
    // Open file
    csv_file = ofstream(tmp_folder + "ptree.csv");
    try{
        for (auto const entry: memory_storage){
            csv_file << '.';
		    csv_file << '"' << entry.first << "\",";
            csv_file << '"' << std::get<0>(entry.second) << "\",";
            csv_file << '"' << std::get<1>(entry.second) << "\",";
            csv_file << '"' << std::get<2>(entry.second) << "\",";
            csv_file << '"' << std::get<3>(entry.second) << "\",";
            csv_file << "\n";
        }
        csv_file.close();
    	execute_query(insert_ptree_stmt.first + tmp_folder + "ptree.csv" + insert_ptree_stmt.second);
    }catch (exception &e){
        syslog(LOG_CRIT, "commit of the ptree to database failed!\nthe ptree will not be saved into DB because %s", e.what());
    }
}

