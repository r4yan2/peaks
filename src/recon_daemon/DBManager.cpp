#include <sys/syslog.h>
#include <cstring>
#include <sstream>
#include <thread>
#include "DBManager.h"
#include "NTL/ZZ_p.h"
#include <common/config.h>
#include <common/utils.h>
#include <recon_daemon/Bitset.h>
#include <OpenPGP.h>
#include <recon_daemon/Message.h>

using namespace peaks::common;
using namespace std;

namespace peaks{
namespace recon{
RECON_DBManager::RECON_DBManager():
    DBManager()
{
	tables = {
        Utils::TABLES::PTREE,
	};
}

RECON_DBManager::~RECON_DBManager(){}

std::vector<std::string> Recon_memory_DBManager::fetch_removed_elements(){
    throw std::runtime_error("Cannot fetch removed elements from memory database manager");
}


std::vector<std::string> Recon_mysql_DBManager::get_all_hash(){
    throw std::runtime_error("Useless to fetch hashes from the database in mysql database manager");
};


std::shared_ptr<DBResult> Recon_mysql_DBManager::get_all_hash_iterator(int limit, int offset){
    throw std::runtime_error("Useless to fetch hashes from the database in mysql database manager");
};

std::string Recon_mysql_DBManager::get_hash_from_results(const std::shared_ptr<DBResult> & results){
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
    Buffer tmp;
    tmp.write_zz_array(n.svalues);
    insert_pnode_stmt->setString(3, tmp.to_str());
    insert_pnode_stmt->setInt(4, n.num_elements);
    insert_pnode_stmt->setBoolean(5, n.leaf);
    tmp.clear();
    tmp.write_zz_array(n.elements);
    insert_pnode_stmt->setString(6, tmp.to_str());
    insert_pnode_stmt->execute();
  }
  catch (std::exception &e){
      syslog(LOG_ERR, "inserting pnode failed - %s", e.what());
    }
  }
  
void Recon_mysql_DBManager::update_node(const DBStruct::node &n){
  try{
    Buffer tmp;
    tmp.write_zz_array(n.svalues);
    update_pnode_stmt->setString(1, tmp.to_str());
    update_pnode_stmt->setInt(2, n.num_elements);
    update_pnode_stmt->setBoolean(3, n.leaf);
    tmp.clear();
    tmp.write_zz_array(n.elements);
    update_pnode_stmt->setString(4, tmp.to_str());
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

  std::vector<NTL::ZZ_p> node_svalues = Buffer(result->getString("node_svalues")).read_zz_array();
  std::vector<NTL::ZZ_p> node_elements = Buffer(result->getString("node_elements")).read_zz_array();
  DBStruct::node n = {
      k.blob(),
      k.size(),
      node_svalues,
      result->getInt("num_elements"),
      result->getBoolean("leaf"),
      node_elements,
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

    get_all_hash_stmt = prepare_query("SELECT hash FROM gpg_keyserver");

    get_all_hash_iterator_stmt = prepare_query("SELECT hash FROM gpg_keyserver LIMIT ? OFFSET ?");

    get_hash_count_stmt = prepare_query("SELECT count(hash) as res FROM gpg_keyserver");

    check_key_stmt = prepare_query("SELECT * FROM gpg_keyserver where hash = (?)");

    insert_ptree_stmt = make_pair<string, string>(
            "LOAD DATA LOCAL INFILE '", "' IGNORE INTO TABLE ptree FIELDS TERMINATED BY ',' ENCLOSED BY '\"' "
            "LINES TERMINATED BY '\\n' (@node_key, key_size, @node_svalues, num_elements, leaf, @node_elements) SET node_key = UNHEX(@node_key), node_svalues = UNHEX(@node_svalues), node_elements = UNHEX(@node_elements)"
            );

}

void Recon_memory_DBManager::insert_node(const DBStruct::node &n){
    //syslog(LOG_DEBUG, "inserting node %s into memory DB", n.key.to_string().c_str());
    auto res = memory_storage.insert(
        std::make_pair(
            std::make_pair(
                n.key, n.key_size
            ),
            DBvalue({
                .svalues = n.svalues,
                .num_elements = n.num_elements,
                .leaf = n.leaf,
                .elements = n.elements
            })
        )
    );
    if (!res.second)
        std::cout << "ERROR in memory DB" << std::endl;
}
  
void Recon_memory_DBManager::update_node(const DBStruct::node &n){
    try{
        auto key = std::make_pair(n.key, n.key_size);
        memory_storage.at(key).svalues = n.svalues;
        memory_storage.at(key).num_elements = n.num_elements;
        memory_storage.at(key).leaf = n.leaf;
        memory_storage.at(key).elements = n.elements;
    }catch(std::exception &e){
        throw std::runtime_error("update pnode failed");
    }
}

DBStruct::node Recon_memory_DBManager::get_node(const Bitset& k){
    DBStruct::node n;
    n.key = k.blob();
    n.key_size = k.size();
    try{
        DBvalue val = memory_storage.at(std::make_pair(n.key, n.key_size));
        n.svalues = val.svalues;
        n.elements = val.elements;
        n.leaf = val.leaf;
        n.num_elements = val.num_elements;
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


int Recon_memory_DBManager::get_hash_count(){
    std::unique_ptr<DBResult> result = get_hash_count_stmt->execute();
    if (result->next()){
        return result->getInt("res");
    }
    return 0;
}

std::shared_ptr<DBResult> Recon_memory_DBManager::get_all_hash_iterator(int limit, int offset){
    get_all_hash_iterator_stmt->setInt(1, limit);
    get_all_hash_iterator_stmt->setInt(2, offset);
    std::unique_ptr<DBResult> result = get_all_hash_iterator_stmt->execute();
    return result;
}

std::string Recon_memory_DBManager::get_hash_from_results(const std::shared_ptr<DBResult> & results){
    std::string hash = "";
    if(results->next()){
        hash = results->getString("hash");
    }
    return hash;
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

void Recon_memory_DBManager::write_memtree_csv(){
    // Open file
    csv_file = ofstream(CONTEXT.dbsettings.tmp_folder + "ptree.csv");
    for (const auto& entry: memory_storage){
        Buffer tmp;
        tmp.write_zz_array(entry.second.svalues);
        std::string node_svalues = hexlify(tmp.to_str());
        tmp.clear();
        tmp.write_zz_array(entry.second.elements);
        std::string node_elements = hexlify(tmp.to_str());
        csv_file << '"' << hexlify(entry.first.first) << "\","; //node key
        csv_file << '"' << entry.first.second << "\","; // node key size
        csv_file << '"' << node_svalues << "\","; // svalues
        csv_file << '"' << entry.second.num_elements << "\","; //num elements
        csv_file << '"' << entry.second.leaf << "\","; // leaf
        csv_file << '"' << node_elements << "\","; //elements
        csv_file << "\n";
    }
    csv_file.close();
}

void Recon_memory_DBManager::commit_memtree(){
    auto f = CONTEXT.dbsettings.tmp_folder + "ptree.csv";
    try{
    	execute_query(insert_ptree_stmt.first + f + insert_ptree_stmt.second);
    }catch (exception &e){
        syslog(LOG_CRIT, "commit of the ptree to database failed!\nthe ptree will not be saved into DB because %s", e.what());
    }
    remove(f.c_str());
}

}
}
