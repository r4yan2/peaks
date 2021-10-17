#include <sys/syslog.h>
#include <cstring>
#include <sstream>
#include <thread>
#include "DBManager.h"
#include "recon_daemon/Utils.h"
#include <common/config.h>
#include <recon_daemon/Bitset.h>

using namespace peaks::common;
using namespace std;

namespace peaks{
namespace recon{
RECON_DBManager::RECON_DBManager():
    DBManager()
{
	tables = {
		{1, "ptree"}
	};
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

Recon_mysql_DBManager::Recon_mysql_DBManager():
    RECON_DBManager()
{
    connect_schema();
    prepare_queries();
}

void Recon_mysql_DBManager::prepare_queries(){
    
    get_pnode_stmt = prepare_query("SELECT * FROM ptree WHERE node_key = (?) and key_size = (?)");

    insert_pnode_stmt = prepare_query("INSERT INTO ptree VALUES (?,?,?,?,?,?)");

    update_pnode_stmt = prepare_query("UPDATE ptree SET node_svalues = (?), num_elements = (?), leaf = (?), node_elements = (?) WHERE node_key = (?) and key_size = (?)");
                                      
    delete_pnode_stmt = prepare_query("DELETE FROM ptree WHERE node_key = (?) and key_size = (?)");

    check_key_stmt = prepare_query("SELECT * FROM gpg_keyserver where hash = (?)");

	insert_ptree_stmt = make_pair<string, string>(
            "LOAD DATA LOCAL INFILE '", "' IGNORE INTO TABLE ptree FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
            "LINES TERMINATED BY '\\n' (@node_key, key_size, node_svalues, num_elements, leaf, node_elements) SET node_key = UNHEX(@node_key)"
            );

	get_removed_hash_stmt = prepare_query("select hash from removed_hash");

	truncate_removed_hash_stmt = prepare_query("truncate removed_hash");

}

void Recon_mysql_DBManager::insert_node(const DBStruct::node &n){
  try{
    insert_pnode_stmt->setString(1, n.key);
    insert_pnode_stmt->setInt(2, n.key_size);
    insert_pnode_stmt->setString(3, RECON_Utils::marshall_vec_zz_p(n.svalues));
    insert_pnode_stmt->setInt(4, n.num_elements);
    insert_pnode_stmt->setBoolean(5, n.leaf);
    insert_pnode_stmt->setString(6, RECON_Utils::marshall_vec_zz_p(n.elements));
    insert_pnode_stmt->execute();
  }
  catch (std::exception &e){
      syslog(LOG_ERR, "inserting pnode failed - %s", e.what());
    }
  }
  
void Recon_mysql_DBManager::update_node(const DBStruct::node &n){
  try{
    update_pnode_stmt->setString(1, RECON_Utils::marshall_vec_zz_p(n.svalues));
    update_pnode_stmt->setInt(2, n.num_elements);
    update_pnode_stmt->setBoolean(3, n.leaf);
    update_pnode_stmt->setString(4, RECON_Utils::marshall_vec_zz_p(n.elements));
    update_pnode_stmt->setString(5, n.key);
    update_pnode_stmt->setInt(6, n.key_size);
    update_pnode_stmt->execute();
  }
  catch (std::exception &e){
      syslog(LOG_ERR, "update pnode failed - %s", e.what());
    }
}

DBStruct::node Recon_mysql_DBManager::get_node(const Bitset& k){
  get_pnode_stmt->setString(1, k.blob());
  get_pnode_stmt->setInt(2, k.size());
  std::unique_ptr<DBResult> result = get_pnode_stmt->execute();
  result->next();
  DBStruct::node n = {
      k.blob(),
      k.size(),
      RECON_Utils::unmarshall_vec_zz_p(result->getString("node_svalues")),
      result->getInt("num_elements"),
      result->getBoolean("leaf"),
      RECON_Utils::unmarshall_vec_zz_p(result->getString("node_elements"))
  };
  return n;
}

void Recon_mysql_DBManager::delete_node(const Bitset& k){
  try{
    delete_pnode_stmt->setString(1,k.blob());
    delete_pnode_stmt->setInt(2,k.size());
    delete_pnode_stmt->execute();
  } catch (exception &e){
    syslog(LOG_WARNING, "Hash not found: %s", Bitset::to_string(k).c_str());
  }
}

bool Recon_mysql_DBManager::check_key(const std::string& k){
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

Recon_memory_DBManager::Recon_memory_DBManager() : RECON_DBManager(){
    connect_schema();
    prepare_queries();
}

void Recon_memory_DBManager::prepare_queries(){

    get_all_hash_stmt = prepare_query("SELECT hash FROM gpg_keyserver LIMIT 10000");

    check_key_stmt = prepare_query("SELECT * FROM gpg_keyserver where hash = (?)");

    insert_ptree_stmt = make_pair<string, string>(
            "LOAD DATA LOCAL INFILE '", "' IGNORE INTO TABLE ptree FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
            "LINES TERMINATED BY '\\n' (@node_key, key_size, node_svalues, num_elements, leaf, node_elements) SET node_key = UNHEX(@node_key)"
            );

}

void Recon_memory_DBManager::insert_node(const DBStruct::node &n){
    //syslog(LOG_DEBUG, "inserting node %s into memory DB", n.key.to_string().c_str());
    auto res = memory_storage.insert(
        std::make_pair(
            std::make_pair(
                n.key, n.key_size
            ),
            std::make_tuple(
                n.svalues, n.num_elements, n.leaf, n.elements
            )
        )
    );
    if (!res.second)
        std::cout << "ERROR in memory DB" << std::endl;
}
  
void Recon_memory_DBManager::update_node(const DBStruct::node &n){
    try{
        memory_storage.at(std::make_pair(n.key, n.key_size)) = std::make_tuple(n.svalues, n.num_elements, n.leaf, n.elements);
    }catch(std::exception &e){
        throw std::runtime_error("update pnode failed");
    }
}

DBStruct::node Recon_memory_DBManager::get_node(const Bitset& k){
    DBStruct::node n;
    n.key = k.blob();
    n.key_size = k.size();
    try{
        std::tie(n.svalues, n.num_elements, n.leaf, n.elements) = memory_storage.at(std::make_pair(n.key, n.key_size));
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

void Recon_memory_DBManager::delete_node(const Bitset& k){
    syslog(LOG_DEBUG, "deleting node %s from memory DB", Bitset::to_string(k).c_str());
  try{
        memory_storage.erase(std::make_pair(k.blob(), k.size()));
  } catch (exception &e){
      throw std::runtime_error("delete pnode failed");
  }
}

bool Recon_memory_DBManager::check_key(const std::string& k){
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
    csv_file = ofstream(CONTEXT.dbsettings.tmp_folder + "ptree.csv");
    try{
        for (const auto& entry: memory_storage){
            std::string node_svalues = RECON_Utils::marshall_vec_zz_p(std::get<0>(entry.second)); 
            std::string node_elements = RECON_Utils::marshall_vec_zz_p(std::get<3>(entry.second)); 
		    csv_file << '"' << hexlify(entry.first.first) << "\","; //node key
		    csv_file << '"' << entry.first.second << "\","; // node key size
            csv_file << '"' << node_svalues << "\","; // svalues
            csv_file << '"' << std::get<1>(entry.second) << "\","; //num elements
            csv_file << '"' << std::get<2>(entry.second) << "\","; // leaf
            csv_file << '"' << node_elements << "\","; //elements
            csv_file << "\n";
        }
        csv_file.close();
    	execute_query(insert_ptree_stmt.first + CONTEXT.dbsettings.tmp_folder + "ptree.csv" + insert_ptree_stmt.second);
    }catch (exception &e){
        syslog(LOG_CRIT, "commit of the ptree to database failed!\nthe ptree will not be saved into DB because %s", e.what());
    }
}

}
}
