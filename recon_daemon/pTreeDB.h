#ifndef RECON_PTREEDB_H
#define RECON_PTREEDB_H

#include "PTree_settings.h"
#include "DBManager.h"
#include "Utils.h"
#include <syslog.h>
#include <iostream>
#include <boost/dynamic_bitset.hpp>
#include <stdexcept>

using namespace NTL;
using namespace PTree_settings;

typedef boost::dynamic_bitset<unsigned char> bitset;

//finite field used by sks keyserver;

class Pnode;

class Ptree{
protected: 
  std::shared_ptr<DBManager> dbm;
  Vec<ZZ_p> points;
  Pnode* root;
  
public:
  Ptree();
  Ptree(std::shared_ptr<DBManager> dbm, Vec<ZZ_p> points);
  ~Ptree();
 
  //getters
  Pnode* get_root();
  Vec<ZZ_p> get_points();
  
  Vec<ZZ_p> add_element_array(ZZ_p z);
  Vec<ZZ_p> delete_element_array(ZZ_p z);
  
  void create();

  //search for a specific node in the DB
  Pnode* get_node(std::string key);

  bool has_key(std::string key);
  void insert(ZZ_p z);

  Pnode* new_child(Pnode* parent, int child_index);
  //insert a new node
  Pnode* node(bitset bs);

  void populate();
  
  void remove(ZZ_p z);
};

class Pnode: public Ptree{
private:
  std::string node_key;
  Vec<ZZ_p> node_svalues;
  bool leaf;
  int num_elements;
  Vec<ZZ_p> node_elements;

public:
  Pnode(std::shared_ptr<DBManager>);
  ~Pnode();
  
  void set_node_key(std::string key);
  void set_node_svalues(Vec<ZZ_p> svalues);
  void set_num_elements(int num);
  void set_leaf(bool b);
  void set_node_elements(Vec<ZZ_p> elements);
  
  std::string get_node_key();
  Vec<ZZ_p> get_node_svalues();
  int get_num_elements();
  bool is_leaf();
  Vec<ZZ_p> get_node_elements();
  
  std::vector<Pnode*> children();
  void commit_node();
  void delete_node();
  void delete_elements();
  void delete_element(ZZ_p elem);
  Vec<ZZ_p> elements();
  void join();
  void insert(ZZ_p z, Vec<ZZ_p> marray, bitset bs, int depth);
  void insert_element(ZZ_p elem);
  int next(bitset bs, int depth);
  Pnode* parent();
  void remove(ZZ_p z, Vec<ZZ_p> marray, bitset bs, int depth);
  int size();
  void split(int depth);
  Vec<ZZ_p> svalues();
  void update_svalues(Vec<ZZ_p> marray, ZZ_p z);
};
#endif //RECON_PTREEDB_H
