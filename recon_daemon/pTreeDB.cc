#include "pTreeDB.h"

Ptree::Ptree(){
}

Ptree::Ptree(std::shared_ptr<RECON_DBManager> dbp, std::vector<NTL::ZZ_p> point){
  root = NULL;
  dbm = dbp;
  points = point;
}

Ptree::~Ptree(){}

Pnode* Ptree::get_root(){
    return root;
}

std::vector<NTL::ZZ_p>Ptree::get_points(){
  return points;
}

std::vector<NTL::ZZ_p> Ptree::add_element_array(NTL::ZZ_p z){
  std::vector<NTL::ZZ_p> marray(points.size());
  for(int i=0; i<points.size(); i++){
    marray[i] = points[i] - z;
    if (marray[i] == 0) throw std::invalid_argument("marray element 0");
  }
  return marray;
}

std::vector<NTL::ZZ_p> Ptree::delete_element_array(NTL::ZZ_p z){
  std::vector<NTL::ZZ_p> marray(points.size());
  for(int i=0; i<points.size(); i++){
    marray[i] = inv(points[i] - z);
  }
  return marray;
}

void Ptree::create(){
  if (get_root()==NULL){
      bitset bs;
      root = node(bs);
      if (root == NULL){
        root = new_child(NULL, 0);
        root->commit_node(true);
      }
  }
}

Pnode* Ptree::get_node(std::string key){
  DBStruct::node n = dbm->get_node(key);
  std::vector<NTL::ZZ_p> node_elements = Utils::unmarshall_vec_zz_p(n.elements);
  std::vector<NTL::ZZ_p> node_svalues = Utils::unmarshall_vec_zz_p(n.svalues);
  Pnode* nd = new Pnode(dbm);
  nd->set_node_key(key);
  nd->set_node_svalues(node_svalues);
  nd->set_num_elements(n.num_elements);
  nd->set_leaf(n.leaf);
  nd->set_node_elements(node_elements);
  //std::ostringstream os;
  //os << "Fetched node: " << nd->get_node_key() << ", num_elements: " << nd->get_num_elements() << ", node elements size: " << nd->get_node_elements().size() << ", leaf " << nd->is_leaf();
  //g_logger.log(Logger_level::DEBUG, os.str());
  return nd;
} 

bool Ptree::has_key(std::string key){
  return dbm->check_key(key);
}

void Ptree::insert(std::string hash, bool build){
    if (!build && has_key(hash)){
      g_logger.log(Logger_level::WARNING, "Blocked insert of duplicate node!");
      return;
    }
    NTL::ZZ_p elem = Utils::hex_to_zz(hash);
    insert(elem);
}

void Ptree::insert(NTL::ZZ_p z){
    bitset bs = Utils::ZZp_to_bitset(z);
    std::string key;
    to_string(bs, key);
    Pnode* root_node = get_root();
    std::vector<NTL::ZZ_p> marray = add_element_array(z);
    root_node->insert(z, marray, bs, 0);
}

Pnode* Ptree::new_child(Pnode* parent, int child_index){
  Pnode* n = new Pnode(dbm);
  n->set_leaf(true);
  bitset key;
  if (parent != NULL){
    std::string parent_key_string = parent->get_node_key();
    key = bitset(parent_key_string);
    int key_size = key.size();
    key.resize(key_size + recon_settings.bq);
    for (int j=0; j<recon_settings.bq; j++){
       if (((1<<uint32_t(j))&child_index) == 0) {
         key.reset(key_size + j);
       } else {
         key.set(key_size + j);
          }
    }
  }
  std::string node_key;
  to_string(key, node_key);
  if (parent!=NULL)
    g_logger.log(Logger_level::DEBUG, "Creating node with key" + node_key + " son of " + parent->get_node_key());
  n->set_node_key(node_key);
  std::vector<NTL::ZZ_p> svalues(recon_settings.num_samples);
  for (int i=0; i < recon_settings.num_samples; i++){
    NTL::ZZ_p z(1);
    svalues[i] = z;
  }
  n->set_node_svalues(svalues);
  return n;
}

Pnode* Ptree::node(bitset key){
   
    std::string str_key;
    if (key.size() == 0)
        str_key = "";
    else
        to_string(key, str_key);
    Pnode* n = NULL;
    while(1){
        try{
            n = get_node(str_key);
            break;
        }   catch (std::exception &e){
            g_logger.log(Logger_level::WARNING, "Errore nel recupero del nodo!");
            std::cout << e.what();
        }
        if (key.size() == 0) break;
  
        key.resize(key.size() - recon_settings.bq);
        to_string(key, str_key);
    }
    return n;
}

void Ptree::remove(NTL::ZZ_p z){
  bitset bs = Utils::ZZp_to_bitset(z);
  std::string key;
  to_string(bs, key);
  try{
    dbm->get_node(key);
  }catch (...){
    syslog(LOG_NOTICE, "No node to delete");
  }

  Pnode* root = get_root();
  std::vector<NTL::ZZ_p> marray = delete_element_array(z);
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

std::vector<NTL::ZZ_p> Pnode::get_node_svalues(){
  return node_svalues;
}

std::string Pnode::get_node_key(){
  return node_key;
}

bool Pnode::is_leaf(){
  return leaf;
}

std::vector<NTL::ZZ_p> Pnode::get_node_elements(){
    return node_elements;
}

void Pnode::set_node_key(std::string new_key){
    node_key = new_key;
}

void Pnode::set_num_elements(int num){
    num_elements = num;
}

void Pnode::set_node_svalues(std::vector<NTL::ZZ_p> new_values){
    node_svalues = new_values;
}

void Pnode::set_node_elements(std::vector<NTL::ZZ_p> new_elements){
    node_elements = new_elements;
}

void Pnode::set_leaf(bool new_leaf){
    leaf = new_leaf;
}

Pnode* Pnode::children(int c_index){
    if (is_leaf())
        return NULL;
    std::string key = get_node_key();
    bitset child_key(key);
    int key_size = child_key.size();
    child_key.resize(key_size + recon_settings.bq);
    for (int j=0; j<recon_settings.bq; j++){
      if ((1<<uint32_t(j)&c_index) == 0){
        child_key.reset(key_size + j);
      }
      else{
        child_key.set(key_size + j);
      }
    }
    Pnode* child = node(child_key);
    return child;
}

std::vector<Pnode*> Pnode::children(){
  std::vector<Pnode*> result;
  if (is_leaf()){
    return result;
  }
  std::string key = get_node_key();
  auto num_children = 1 << uint32_t(recon_settings.bq);
  for (int i=0; i < num_children; i++){
    bitset child_key(key);
    int key_size = child_key.size();
    child_key.resize(key_size + recon_settings.bq);
    for (int j=0; j<recon_settings.bq; j++){
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

void Pnode::commit_node(bool newnode){
  DBStruct::node n;
  n.key = node_key;
  n.svalues = Utils::marshall_vec_zz_p(get_node_svalues());
  n.num_elements = num_elements;
  n.leaf = leaf;
  n.elements = Utils::marshall_vec_zz_p(get_node_elements());
  //std::ostringstream os;
  //os << "committing node:\nnode_key " << n.key << " num elements " << n.num_elements << " leaf " << n.leaf << "node elements number" << get_node_elements().size() << " is a newnode?" << newnode << std::endl;
  //g_logger.log(Logger_level::DEBUG, os.str());
  if (newnode)
      dbm->insert_node(n);
  else
      dbm->update_node(n);
}

void Pnode::delete_node(){
  dbm->delete_node(node_key);
}

void Pnode::delete_elements(){
  node_elements.clear();
  commit_node();
}

void Pnode::delete_element(NTL::ZZ_p elem){
  std::vector<NTL::ZZ_p> new_elements;
  for (auto element : node_elements){
    if (element != elem) new_elements.push_back(element);  
  }
  node_elements = new_elements;
  commit_node();
}

std::vector<NTL::ZZ_p> Pnode::elements(){
  std::vector<NTL::ZZ_p> result;
  if (is_leaf()){
    result = node_elements;
  } else{
    std::vector<Pnode*> children_vec;
    children_vec = children();
    for (auto child: children_vec){
      std::vector<NTL::ZZ_p> elements = child->get_node_elements();
      result.insert(result.end(), elements.begin(), elements.end());
      delete child;
    }
  }
  return result;
}

void Pnode::join(){
  std::vector<NTL::ZZ_p> elements;
  std::vector<Pnode*> children_vec;
  try{
    children_vec = children();
  }catch (...){
    syslog(LOG_NOTICE, "Nodo figlio inesistente");
  }
  for (auto child : children_vec){
    std::vector<NTL::ZZ_p> elems = child->node_elements;
    elements.insert(elements.end(), elems.begin(), elems.end());
    child->delete_node();
    delete child;
  }
  node_elements = elements;
  leaf = true;
  commit_node();
}

void Pnode::insert_element(NTL::ZZ_p elem){
    //g_logger.log(Logger_level::DEBUG, "inserted element into node");
  node_elements.push_back(elem);
}

int Pnode::next(bitset bs, int depth){
    int key;
    key = next_hockeypuck(bs, depth);
    g_logger.log(Logger_level::DEBUG, "Calculated key hockeypuck way " + std::to_string(key));
    key = next_sks(bs, depth);
    g_logger.log(Logger_level::DEBUG, "Calculated key sks way " + std::to_string(key));
    return key;
}

int Pnode::next_hockeypuck(bitset bs, int depth){
  if (is_leaf()){
    throw std::invalid_argument("il nodo è una foglia e tu vorresti i successori?");
  }
  int childIndex = 0;
  for (int i=0; i<recon_settings.bq; i++){
    auto mask = 1 << uint32_t(i);
    if (bs.test(depth*recon_settings.bq+i)) childIndex |= mask;
  }
  return childIndex;
}

int Pnode::next_sks(bitset bs, int depth){
    int lowbit = depth * recon_settings.bq;
    int highbit = lowbit + recon_settings.bq + 1;
    int lowbyte = lowbit / 8;
    lowbit = lowbit % 8;
    int highbyte = highbit / 8;
    highbit = highbit % 8;

    std::string rev;
    to_string(bs, rev);
    std::reverse(rev.begin(), rev.end());
    bitset newbs(rev);

    std::vector<unsigned char> blocks;
    to_block_range(newbs, std::back_inserter(blocks));
    int key;
    if (lowbyte == highbyte){
        bitset byte;
        byte.append(blocks[lowbyte]);
        key = ((byte.to_ulong() >> (7 - highbit)) & (255 >> (8 - highbit - lowbit + 1)));
    }
    else{
        bitset byte1;
        byte1.append(blocks[lowbyte]);
        bitset byte2;
        byte2.append(blocks[highbyte]);
        int key1 = (byte1.to_ulong() & (255 >> (8 - 8 - lowbit))) << (highbit + 1);
        int key2 = (byte2.to_ulong() & (255 << (8 - highbit + 1))) >> (7 - highbit);
        key = key1 | key2;
    }
    return key;
}

void Pnode::split(int depth){
  std::vector<NTL::ZZ_p> split_elements(node_elements);
  leaf = false;
  node_elements.clear();
  if ((node_elements.size() != 0) || (split_elements.size() == 0))
      g_logger.log(Logger_level::CRITICAL, "you did something wrong");
  
  commit_node();

  //create child nodes
  auto num = 1 << uint32_t(recon_settings.bq);
  std::vector<Pnode*> child_vec;

  for (uint32_t i=0; i< num; i++){
    Pnode* child_node = new_child(this, i);
    child_node->commit_node(true);
    child_vec.push_back(child_node);
  }
  //move elements into child nodes
  for (auto z : split_elements){
    bitset bs = Utils::ZZp_to_bitset(z);

    int index = next(bs, depth);
    Pnode* child_node = child_vec[index];
    std::vector<NTL::ZZ_p> marray = child_node->add_element_array(z);
    child_node->insert(z, marray, bs, depth+1);
  }
  
  //cleanup
  for (Pnode* n : child_vec)
      delete n;
}

Pnode* Pnode::parent(){
  std::string key = get_node_key();
  if (key.size()==0) return NULL;
  bitset parent_key(key);
  parent_key.resize(key.size() - recon_settings.bq);
  std::string parent_key_str;
  to_string(parent_key, parent_key_str);
  Pnode* parent = get_node(parent_key_str);
  return parent;
}
 
void Pnode::remove(NTL::ZZ_p z, std::vector<NTL::ZZ_p> marray, bitset bs, int depth){
  Pnode *cur_node = this;
  while(1){
    cur_node->update_svalues(marray,z);
    cur_node->set_num_elements(cur_node->get_num_elements() - 1);
    if (cur_node->is_leaf()){
      break;
    } else{
      if (cur_node->get_num_elements() <= recon_settings.join_threshold){
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

void Pnode::update_svalues(std::vector<NTL::ZZ_p> marray, NTL::ZZ_p z){
  if (marray.size() != get_points().size()) syslog(LOG_NOTICE, "marray e points sono di dimensione diversa!");
  for (long i=0; i < marray.size(); i++){
      node_svalues[i] = node_svalues[i] * marray[i];
  }
}

void Pnode::insert(NTL::ZZ_p z, std::vector<NTL::ZZ_p> marray, bitset bs, int depth){
    Pnode* cur_node = this;
    while(1){
        cur_node->update_svalues(marray, z);
        cur_node->set_num_elements(cur_node->get_num_elements() + 1);
        if (cur_node->is_leaf()){
            //g_logger.log(Logger_level::DEBUG, "current node is a leaf, number of elements " + std::to_string(cur_node->get_node_elements().size()));
            if (cur_node->get_node_elements().size() > recon_settings.split_threshold){
                //g_logger.log(Logger_level::DEBUG, "...splitting!");
                cur_node->split(depth);
            }
            else {
                std::ostringstream os;
                os << z;
                g_logger.log(Logger_level::DEBUG, "Inserting " + os.str() + " to node " + cur_node->node_key);
                cur_node->insert_element(z);
                cur_node->commit_node();
                return;
            }
        }
        //g_logger.log(Logger_level::DEBUG, "current node is an intermediate, searching the next one...");
        cur_node->commit_node();
        
        int child_index = cur_node->next(bs, depth);
        cur_node = cur_node->children(child_index);
        /*
        std::vector<Pnode*> child_vec = cur_node->children();
        cur_node = child_vec[child_index];
        */

        depth += 1;
    }
}

