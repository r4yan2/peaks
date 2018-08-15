#ifndef RECON_PTREEDB_H
#define RECON_PTREEDB_H

#include "RECON_DBManager.h"
#include "Utils.h"
#include <syslog.h>
#include <iostream>
#include <boost/dynamic_bitset.hpp>
#include <stdexcept>
#include "logger.h"
#include "Recon_settings.h"

typedef boost::dynamic_bitset<unsigned char> bitset;

class Pnode;

class Ptree{
protected: 
  Pnode* root;
  std::shared_ptr<RECON_DBManager> dbm;
  std::vector<NTL::ZZ_p> points;
  
public:
  Ptree();
  Ptree(std::shared_ptr<RECON_DBManager> dbm, std::vector<NTL::ZZ_p> points);
  ~Ptree();
 
  //getters
  Pnode* get_root();
  std::vector<NTL::ZZ_p> get_points();
  
  std::vector<NTL::ZZ_p> add_element_array(NTL::ZZ_p z);
  std::vector<NTL::ZZ_p> delete_element_array(NTL::ZZ_p z);
  
  void create();

  //search for a specific node in the DB
  Pnode* get_node(std::string key);

  bool has_key(std::string key);
  void insert(NTL::ZZ_p z);

  Pnode* new_child(Pnode* parent, int child_index);
  //insert a new node
  Pnode* node(bitset key);

  void populate(std::vector<std::string> hashes);
  
  void remove(NTL::ZZ_p z);
};

class Pnode: public Ptree{
private:
  std::string node_key;
  std::vector<NTL::ZZ_p> node_svalues;
  bool leaf;
  int num_elements;
  std::vector<NTL::ZZ_p> node_elements;

public:
  Pnode(std::shared_ptr<RECON_DBManager>);
  ~Pnode();
  
  void set_node_key(std::string key);
  void set_node_svalues(std::vector<NTL::ZZ_p> svalues);
  void set_num_elements(int num);
  void set_leaf(bool b);
  void set_node_elements(std::vector<NTL::ZZ_p> elements);
  
  std::string get_node_key();
  std::vector<NTL::ZZ_p> get_node_svalues();
  int get_num_elements();
  bool is_leaf();
  std::vector<NTL::ZZ_p> get_node_elements();
  
  std::vector<Pnode*> children();
  void commit_node(bool newnode = false);
  void delete_node();
  void delete_elements();
  void delete_element(NTL::ZZ_p elem);
  std::vector<NTL::ZZ_p> elements();
  void join();
  void insert(NTL::ZZ_p z, std::vector<NTL::ZZ_p> marray, bitset bs, int depth);
  void insert_element(NTL::ZZ_p elem);
  int next(bitset bs, int depth);
  Pnode* parent();
  void remove(NTL::ZZ_p z, std::vector<NTL::ZZ_p> marray, bitset bs, int depth);
  void split(int depth);
  std::vector<NTL::ZZ_p> svalues();
  void update_svalues(std::vector<NTL::ZZ_p> marray, NTL::ZZ_p z);
};
#endif //RECON_PTREEDB_H
