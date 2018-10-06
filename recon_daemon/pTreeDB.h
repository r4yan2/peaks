#ifndef RECON_PTREEDB_H
#define RECON_PTREEDB_H

#include "RECON_DBManager.h"
#include "Recon_settings.h"
#include "Utils.h"
#include <syslog.h>
#include <iostream>
#include <stdexcept>
#include "logger.h"
#include "Bitset.h"
#include "myset.h"
#include <queue>
#include <memory>

typedef Bitset bitset;

class Pnode;
class Memnode;

typedef std::shared_ptr<Pnode> pnode_ptr;
typedef std::shared_ptr<Memnode> memnode_ptr;

class Ptree{
protected: 
  pnode_ptr root;
  std::shared_ptr<RECON_DBManager> dbm;
  std::vector<NTL::ZZ_p> points;
  
public:
  Ptree();
  Ptree(std::shared_ptr<RECON_DBManager> dbp, std::vector<NTL::ZZ_p> point);
  ~Ptree();
 
  //getters
  pnode_ptr get_root();
  std::vector<NTL::ZZ_p> get_points();
  
  std::vector<NTL::ZZ_p> add_element_array(const NTL::ZZ_p &z);
  std::vector<NTL::ZZ_p> delete_element_array(const NTL::ZZ_p &z);
  
  void create();

  //search for a specific node in the DB
  pnode_ptr get_node(const std::string &key);

  bool has_key(const std::string &key);
  void insert(const NTL::ZZ_p &z);
  void insert(const std::string &hash, bool build=false);

  pnode_ptr new_child(pnode_ptr parent, int child_index);
  //insert a new node
  pnode_ptr node(const bitset &key);

  void remove(const NTL::ZZ_p &z);
};

class Pnode: public Ptree, public std::enable_shared_from_this<Pnode>{
    
private:
  std::string node_key;
  std::vector<NTL::ZZ_p> node_svalues;
  bool leaf;
  int num_elements;
  std::vector<NTL::ZZ_p> node_elements;

public:
  Pnode();
  Pnode(std::shared_ptr<RECON_DBManager>, const std::vector<NTL::ZZ_p>&);
  ~Pnode();
  
  void set_node_key(const std::string &key);
  void set_node_svalues(const std::vector<NTL::ZZ_p> &svalues);
  void set_num_elements(int num);
  void set_leaf(bool b);
  void set_node_elements(const std::vector<NTL::ZZ_p> &elements);
  
  std::string get_node_key();
  std::vector<NTL::ZZ_p> get_node_svalues();
  int get_num_elements();
  bool is_leaf();
  std::vector<NTL::ZZ_p> get_node_elements();

  void clear_node_elements();
  
  std::vector<pnode_ptr> children();
  pnode_ptr children(int c_index);
  void commit_node(bool newnode = false);
  void delete_node();
  void delete_elements();
  void delete_element(const NTL::ZZ_p &elem);
  std::vector<NTL::ZZ_p> elements();
  void join();
  void insert(const NTL::ZZ_p &z, const std::vector<NTL::ZZ_p> &marray, const bitset &bs, int depth);
  void insert_element(const NTL::ZZ_p &elem);
  int next(const bitset &bs, int depth);
  int next_sks(const bitset &bs, int depth);
  int next_hockeypuck(const bitset &bs, int depth);
  pnode_ptr parent();
  void remove(const NTL::ZZ_p &z, const std::vector<NTL::ZZ_p> &marray, const bitset &bs, int depth);
  void split(int depth);
  std::vector<NTL::ZZ_p> svalues();
  void update_svalues(const std::vector<NTL::ZZ_p> &marray, const NTL::ZZ_p &z);
};


class MemTree: public Ptree{
    private:
        memnode_ptr root;
        std::shared_ptr<RECON_DBManager> dbm;
        std::vector<NTL::ZZ_p> points;
    public:
        MemTree();
        MemTree(std::shared_ptr<RECON_DBManager>, const std::vector<NTL::ZZ_p>&);
        ~MemTree();
        std::vector<NTL::ZZ_p> get_points();
        memnode_ptr get_node(const std::string &key);
        void commit_memtree();
        memnode_ptr new_child(memnode_ptr parent, int child_index);
        memnode_ptr get_root();
        void insert(const NTL::ZZ_p &z);
        void insert(const std::string &hash);
};

class Memnode: public MemTree, public Pnode{
    private:
        std::vector<memnode_ptr> child_vec;
		memnode_ptr shared_from_this();
    public:
        Memnode();
        ~Memnode();

        void split(int depth);
        void insert(const NTL::ZZ_p &z, const std::vector<NTL::ZZ_p> &marray, const bitset &bs, int depth);
        std::vector<memnode_ptr> children();
        memnode_ptr children(int cindex);
};

#endif //RECON_PTREEDB_H
