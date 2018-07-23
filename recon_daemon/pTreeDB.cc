#include "pTreeDB.h"

Ptree::Ptree(){
}

Ptree::Ptree(std::shared_ptr<RECON_DBManager> dbp, std::vector<ZZ_p> point){
  dbm = dbp;
  points = point;
  root = NULL;
}

Ptree::~Ptree(){}

Pnode* Ptree::get_root(){
  return root;
}

std::vector<ZZ_p>Ptree::get_points(){
  return points;
}

std::vector<ZZ_p> Ptree::add_element_array(ZZ_p z){
  std::vector<ZZ_p> marray(points.size());
  for(int i=0; i<points.size(); i++){
    marray[i] = points[i] - z;
    if (IsZero(marray[i])) throw std::invalid_argument("marray is 0");
  }
  return marray;
}

std::vector<ZZ_p> Ptree::delete_element_array(ZZ_p z){
  std::vector<ZZ_p> marray(points.size());
  for(int i=0; i<points.size(); i++){
    marray[i] = inv(points[i] - z);
  }
  return marray;
}

void Ptree::create(){
  if (get_root()==NULL){
    root = new_child(NULL, 0);
    root->commit_node();
  }
}

Pnode* Ptree::get_node(std::string key){
  DBStruct::node n = dbm->get_node(key);
  std::vector<ZZ_p> node_elements = Utils::unmarshall_vec_zz_p(n.elements);
  std::vector<ZZ_p> node_svalues = Utils::unmarshall_vec_zz_p(n.svalues);
  Pnode* nd = new Pnode(dbm);
  nd->set_node_key(key);
  nd->set_node_svalues(node_svalues);
  nd->set_num_elements(n.num_elements);
  nd->set_leaf(n.leaf);
  nd->set_node_elements(node_elements);
  return nd;
} 

bool Ptree::has_key(std::string key){
  try{
    dbm->get_node(key);
    return true;
  } catch (...){
      return false;
  }
}

void Ptree::insert(ZZ_p z){
  bitset bs = Utils::ZZp_to_bitset(z);
  std::string key;
  to_string(bs, key);
  try{
    DBStruct::node res = dbm->get_node(key);
    syslog(LOG_NOTICE, "Tentato inserimento di nodo già presente!");
  }catch (...){ 
    Pnode* root_node = get_root();
    std::vector<ZZ_p> marray = add_element_array(z);
    root_node->insert(z, marray, bs, 0);
    dbm->insert_node(DBStruct::node{key, "", 0, true, ""});
  }
}

Pnode* Ptree::new_child(Pnode* parent, int child_index){
  Pnode* n = new Pnode(dbm);
  n->set_leaf(true);
  bitset key;
  if (parent != NULL){
    std::string parent_key_string = parent->get_node_key();
    key = bitset(parent_key_string);
    int key_size = key.size();
    key.resize(key_size + bq);
    for (int j=0; j<bq; j++){
       if (((1<<uint32_t(j))&child_index) == 0) {
         key.reset(key_size + j);
       } else {
         key.set(key_size + j);
          }
    }
  }
  std::string node_key;
  to_string(key, node_key);
  n->set_node_key(node_key);
  std::vector<ZZ_p> svalues(num_samples);
  for (int i=0; i<num_samples; i++){
    ZZ_p z(1);
    svalues[i] = z;
  }
  n->set_node_svalues(svalues);
  return n;
}

Pnode* Ptree::node(bitset bs){
  if (bs.size() == 0) throw std::invalid_argument("received a bs of 0 size");
  bitset key = bs;
 
  std::string n_key;
  to_string(bs, n_key);
  Pnode* n;
  while(1){
    try{
      n = get_node(n_key);
      break;
    } catch (std::exception &e){
      syslog(LOG_NOTICE, "Errore nel recupero del nodo!");
      std::cout << e.what();
    }
    if (key.size() == 0) break;

    key.resize(key.size() - bq);
    to_string(key, n_key);
  }
  return n;
}

void Ptree::populate(std::vector<std::string> hashes){
    ZZ_p base(16);
    for (auto hash : hashes){
        ZZ_p new_elem;
        size_t limit = hash.size();
        for (size_t i=1; i <= limit; i++){
            char hexchar = hash[limit - i];
            int val = (hexchar >= 'A') ? (hexchar - 'A' + 10) : (hexchar - '0');            
            ZZ_p res;
            power(res, base,(i-1));
            new_elem += conv<ZZ_p>(val) * res;
        }
        insert(new_elem);
    }
}

void Ptree::remove(ZZ_p z){
  bitset bs = Utils::ZZp_to_bitset(z);
  std::string key;
  to_string(bs, key);
  try{
    dbm->get_node(key);
  }catch (...){
    syslog(LOG_NOTICE, "No node to delete");
  }

  Pnode* root = get_root();
  std::vector<ZZ_p> marray = delete_element_array(z);
  root->remove(z, marray, bs, 0);
  dbm->delete_node(key);
}

Pnode::Pnode(std::shared_ptr<RECON_DBManager> dbp){
    dbm = dbp;
    num_elements = 0;
    //node_key = "";
    //node_svalues = //initialize}
    }
Pnode::~Pnode(){}

int Pnode::get_num_elements(){
  return num_elements;
}

std::vector<ZZ_p> Pnode::get_node_svalues(){
  return node_svalues;
}

std::string Pnode::get_node_key(){
  return node_key;
}

bool Pnode::is_leaf(){
  return leaf;
}

std::vector<ZZ_p> Pnode::get_node_elements(){
    return node_elements;
}

void Pnode::set_node_key(std::string new_key){
    node_key = new_key;
}

void Pnode::set_num_elements(int num){
    num_elements = num;
}

void Pnode::set_node_svalues(std::vector<ZZ_p> new_values){
    node_svalues = new_values;
}

void Pnode::set_node_elements(std::vector<ZZ_p> new_elements){
    node_elements = new_elements;
}

void Pnode::set_leaf(bool new_leaf){
    leaf = new_leaf;
}

std::vector<Pnode*> Pnode::children(){
  std::vector<Pnode*> result;
  if (is_leaf()){
    return result;
  }
  std::string key = get_node_key();
  auto num_children = 1 << uint32_t(bq);
  for (int i=0; i < num_children; i++){
    bitset child_key(key);
    int key_size = child_key.size();
    child_key.resize(key_size + bq);
    for (int j=0; j<bq; j++){
      if ((1<<uint32_t(j)&i) == 0){
        child_key.reset(key_size + j);
      }
      else{
        child_key.set(key_size + j);
      }
    }
    Pnode* child = node(child_key);
    result.push_back(child);
  }
  return result;
}

void Pnode::commit_node(){
  DBStruct::node n;
  n.key = node_key;
  n.svalues = Utils::marshall_vec_zz_p(get_node_svalues());
  n.num_elements = num_elements;
  n.leaf = leaf;
  n.elements = Utils::marshall_vec_zz_p(get_node_elements());
  dbm->insert_node(n);
}

void Pnode::delete_node(){
  dbm->delete_node(node_key);
}

void Pnode::delete_elements(){
  std::vector<ZZ_p> empty;
  node_elements = empty;
  commit_node();
}

void Pnode::delete_element(ZZ_p elem){
  std::vector<ZZ_p> new_elements;
  for (auto element : node_elements){
    if (element != elem) new_elements.push_back(element);  
  }
  node_elements = new_elements;
  commit_node();
}

std::vector<ZZ_p> Pnode::elements(){
  std::vector<ZZ_p> result;
  if (is_leaf()){
    result = node_elements;
  } else{
    std::vector<Pnode*> children_vec;
    children_vec = children();
    for (auto child: children_vec){
      std::vector<ZZ_p> elements = child->get_node_elements();
      result.insert(result.end(), elements.begin(), elements.end());
    }
  }
  return result;
}

void Pnode::join(){
  std::vector<ZZ_p> elements;
  std::vector<Pnode*> children_vec;
  try{
    children_vec = children();
  }catch (...){
    syslog(LOG_NOTICE, "Nodo figlio inesistente");
  }
  for (auto child : children_vec){
    std::vector<ZZ_p> elems = child->node_elements;
    elements.insert(elems.end(), elems.begin(), elems.end());
    child->delete_node();
  }
  node_elements = elements;
  leaf = true;
  commit_node();
}

void Pnode::insert_element(ZZ_p elem){
  node_elements.push_back(elem);
}

int Pnode::next(bitset bs, int depth){
  if (is_leaf()){
    throw std::invalid_argument("il nodo è una foglia e tu vorresti i successori?");
  }
  int childIndex = 0;
  for (int i=0; i<bq; i++){
    auto mask = 1 << uint32_t(i);
    if (bs.test(depth*bq+i)) childIndex |= mask;
  }
  return childIndex;
}

void Pnode::split(int depth){
  std::vector<ZZ_p> split_elements;
  split_elements = node_elements;
  leaf = false;
  node_elements.clear();
  try{
    commit_node();
  }
  catch (...){
    syslog(LOG_NOTICE, "Impossibile committare il nodo!");
  }
  //create child nodes
  auto num = 1 << uint32_t(bq);
  std::vector<Pnode*> child_vec;

  for (int i=0; i< num; i++){
    Pnode* child_node = new_child(this, i);
    try{
      child_node->commit_node();
    }catch (...){
      //do something
    }
    child_vec.push_back(child_node);
  }
  //move elements into child nodes
  for (auto z : split_elements){
    bitset bs = Utils::ZZp_to_bitset(z);

    int index = next(bs, depth);
    Pnode* child_node = child_vec[index];
    std::vector<ZZ_p> marray = child_node->add_element_array(z);
    child_node->insert(z, marray, bs, depth+1);
  }
}

Pnode* Pnode::parent(){
  std::string key = get_node_key();
  if (key.size()==0) return NULL;
  bitset parent_key(key);
  parent_key.resize(key.size() - bq);
  std::string parent_key_str;
  to_string(parent_key, parent_key_str);
  Pnode* parent = get_node(parent_key_str);
  return parent;
}
 
void Pnode::remove(ZZ_p z, std::vector<ZZ_p> marray, bitset bs, int depth){
  Pnode *cur_node = this;
  while(1){
    cur_node->update_svalues(marray,z);
    cur_node->set_num_elements(cur_node->get_num_elements() - 1);
    if (cur_node->is_leaf()){
      break;
    } else{
      if (cur_node->get_num_elements() <= join_threshold){
        try{
          cur_node->join();
        } catch (...){
          syslog(LOG_NOTICE, "Impossibile effettuare il join dei nodi");
        }
        break;
      }
        else {
          try{
            cur_node->commit_node();
          }
          catch (...){
            syslog(LOG_NOTICE, "Impossibile committare il nodo");
          }
          int child_index = cur_node->next(bs, depth);
          std::vector<Pnode*> child_vec;
          try{
              child_vec = cur_node->children();
          } catch (...){
            syslog(LOG_NOTICE, "Impossibile creare nodo figlio");
          }
          cur_node = child_vec[child_index];
          depth++;
        }
      }
    }
    try{
      cur_node->delete_element(z);
    } catch (...){
      syslog(LOG_NOTICE, "errore nella rimozione del node_svalueso");
    }
  cur_node->commit_node();
}

void Pnode::update_svalues(std::vector<ZZ_p> marray, ZZ_p z){
  if (marray.size() != get_points().size()) syslog(LOG_NOTICE, "marray e points sono di dimensione diversa!");
  for (long i=0; i < marray.size(); i++){
      node_svalues[i] = node_svalues[i] * marray[i];
  }
}

void Pnode::insert(ZZ_p z, std::vector<ZZ_p> marray, bitset bs, int depth){
    Pnode* cur_node = this;
    while(1){
        cur_node->update_svalues(marray, z);
        cur_node->set_num_elements(cur_node->get_num_elements() + 1);
        if (cur_node->is_leaf()){
            if (cur_node->get_node_elements().size() > split_threshold){
                cur_node->split(depth);
            }
            else {
                cur_node->insert_element(z);
                cur_node->commit_node();
                return;
            }
        }
        cur_node->commit_node();
        int child_index = cur_node->next(bs, depth);
        std::vector<Pnode*> child_vec = cur_node->children();
        cur_node = child_vec[child_index];
        depth += 1;
    }
}

