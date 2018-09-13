#include "pTreeDB.h"

Ptree::Ptree(){
}

Ptree::Ptree(std::shared_ptr<RECON_DBManager> dbp, std::vector<NTL::ZZ_p> point){
  root = NULL;
  dbm = dbp;
  points = point;
}

Ptree::~Ptree(){}

pnode_ptr Ptree::get_root(){
    return root;
}

std::vector<NTL::ZZ_p>Ptree::get_points(){
  return points;
}

std::vector<NTL::ZZ_p> Ptree::add_element_array(NTL::ZZ_p z){
  std::vector<NTL::ZZ_p> marray(points.size());
  for(size_t i=0; i<points.size(); i++){
    marray[i] = points[i] - z;
    if (marray[i] == 0){
        g_logger.log(Logger_level::CRITICAL, "marray has a zero element!");
        throw std::runtime_error("marray has a zero element");
    }
  }
  return marray;
}

std::vector<NTL::ZZ_p> Ptree::delete_element_array(NTL::ZZ_p z){
  std::vector<NTL::ZZ_p> marray(points.size());
  for(size_t i=0; i<points.size(); i++){
    marray[i] = inv(points[i] - z);
  }
  return marray;
}

void Ptree::create(){
  if (get_root()==NULL){
      bitset bs(0);
      root = node(bs);
      if (root == NULL){
        root = new_child(NULL, 0);
        root->commit_node(true);
      }
  }
}

pnode_ptr Ptree::get_node(std::string key){
  DBStruct::node n = dbm->get_node(key);
  std::vector<NTL::ZZ_p> node_elements = Utils::unmarshall_vec_zz_p(n.elements);
  std::vector<NTL::ZZ_p> node_svalues = Utils::unmarshall_vec_zz_p(n.svalues);
  pnode_ptr nd(new Pnode(dbm, get_points()));
  nd->set_node_key(key);
  nd->set_node_svalues(node_svalues);
  nd->set_num_elements(n.num_elements);
  nd->set_leaf(n.leaf);
  nd->set_node_elements(node_elements);
  return nd;
}

bool Ptree::has_key(std::string key){
  return dbm->check_key(key);
}

void Ptree::insert(std::string hash, bool build){
    NTL::ZZ_p elem = Utils::hex_to_zz(hash);
    insert(elem);
}

void Ptree::insert(NTL::ZZ_p z){
    bitset bs(z);
    pnode_ptr root_node = get_root();
    std::vector<NTL::ZZ_p> marray = add_element_array(z);
    root_node->insert(z, marray, bs, 0);
}

pnode_ptr Ptree::new_child(pnode_ptr parent, int child_index){
  pnode_ptr n(new Pnode(dbm, get_points()));
  n->set_leaf(true);
  bitset key;
  if (parent != NULL){
    std::string parent_key_string = parent->get_node_key();
    key = bitset(parent_key_string);
    int key_size = key.size();
    key.resize(key_size + recon_settings.bq);

    if (recon_settings.sks_bitstring == 0){
        for (int j=0; j<recon_settings.bq; j++){
           if (((1<<j)&child_index) == 0){
             key.clear(key_size + j);
           } else {
             key.set(key_size + j);
              }
        }
    }else{
        for (int j=recon_settings.bq - 1; j>=0; j--){
            if ((child_index & 1) == 1)
                key.set(key_size + j);
            else
                key.clear(key_size + j);
            child_index >>= 1;
        }
    }
  }
  std::string node_key = key.to_string();
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

pnode_ptr Ptree::node(bitset key){
   
    std::string str_key;
    if (key.size() == 0)
        str_key = "";
    else
        str_key = key.to_string();
    pnode_ptr n = NULL;
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
        str_key = key.to_string();
    }
    return n;
}

void Ptree::remove(NTL::ZZ_p z){
  bitset bs(z);
  std::string key = bs.to_string();
  try{
    dbm->get_node(key);
  }catch (...){
    syslog(LOG_NOTICE, "No node to delete");
  }

  pnode_ptr root = get_root();
  std::vector<NTL::ZZ_p> marray = delete_element_array(z);
  root->remove(z, marray, bs, 0);
  dbm->delete_node(key);
}

Pnode::Pnode(){}

Pnode::Pnode(std::shared_ptr<RECON_DBManager> dbp, std::vector<NTL::ZZ_p> point){
    dbm = dbp;
    num_elements = 0;
    points = point;
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

pnode_ptr Pnode::children(int c_index){
    if (is_leaf())
        return NULL;
    std::string key = get_node_key();
    bitset child_key(key);
    int key_size = child_key.size();
    child_key.resize(key_size + recon_settings.bq);

    if (recon_settings.sks_bitstring == 0){
        for (int j=0; j<recon_settings.bq; j++){
          if ((1<<uint32_t(j)&c_index) == 0){
            child_key.clear(key_size + j);
          }
          else{
            child_key.set(key_size + j);
          }
        }
    }else{
        for (int j=recon_settings.bq-1; j>=0; j--){
          if ((c_index & 1) == 1)
              child_key.set(key_size + j);
          else
              child_key.clear(key_size + j);
          c_index >>= 1;
        }
    }

    pnode_ptr child = node(child_key);
    return child;
}

std::vector<pnode_ptr> Pnode::children(){
  std::vector<pnode_ptr> result;
  if (is_leaf()){
    return result;
  }
  std::string key = get_node_key();
  auto num_children = 1 << uint32_t(recon_settings.bq);
  if (recon_settings.sks_bitstring == 1){
      for (int i=num_children - 1; i>= 0; i--){
          bitset child_key(key);
          int key_size = child_key.size();
          child_key.resize(key_size + recon_settings.bq);
          for (int j=recon_settings.bq-1; j>=0; j--){
            if ((i & 1) == 1)
                child_key.set(key_size + j);
            else
                child_key.clear(key_size + j);
            i >>= 1;
          }
          pnode_ptr child = node(child_key);
          result.push_back(child);
      }
      std::reverse(result.begin(), result.end());
  }else{
      for (int i=0; i < num_children; i++){
        bitset child_key(key);
        int key_size = child_key.size();
        child_key.resize(key_size + recon_settings.bq);
        for (int j=0; j<recon_settings.bq; j++){
          if ((1<<uint32_t(j)&i) == 0){
            child_key.clear(key_size + j);
          }
          else{
            child_key.set(key_size + j);
          }
        }
        pnode_ptr child = node(child_key);
        result.push_back(child);
      }
  }
  return result;
}

void Pnode::clear_node_elements(){
    node_elements.clear();
}

void Pnode::commit_node(bool newnode){
  DBStruct::node n;
  n.key = node_key;
  n.svalues = Utils::marshall_vec_zz_p(get_node_svalues());
  n.num_elements = num_elements;
  n.leaf = leaf;
  n.elements = Utils::marshall_vec_zz_p(get_node_elements());
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
    std::vector<pnode_ptr> children_vec;
    children_vec = children();
    for (auto child: children_vec){
      std::vector<NTL::ZZ_p> elements = child->get_node_elements();
      result.insert(result.end(), elements.begin(), elements.end());
    }
  }
  return result;
}

void Pnode::join(){
  std::vector<NTL::ZZ_p> elements;
  std::vector<pnode_ptr> children_vec;
  try{
    children_vec = children();
  }catch (...){
    syslog(LOG_NOTICE, "Nodo figlio inesistente");
  }
  for (auto child : children_vec){
    std::vector<NTL::ZZ_p> elems = child->node_elements;
    elements.insert(elements.end(), elems.begin(), elems.end());
    child->delete_node();
  }
  node_elements = elements;
  leaf = true;
  commit_node();
}

void Pnode::insert_element(NTL::ZZ_p elem){
  node_elements.push_back(elem);
}

int Pnode::next(bitset bs, int depth){
    int key;
    int h_key = next_hockeypuck(bs, depth);
    int s_key = next_sks(bs, depth);
    //g_logger.log(Logger_level::DEBUG, "Calculated next child - hockeypuck: " + std::to_string(h_key) + " sks: " + std::to_string(s_key));
    if (recon_settings.sks_bitstring == 1)
        key = s_key;
    else
        key = h_key;
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
    int highbit = lowbit + recon_settings.bq - 1;
    int lowbyte = lowbit / 8;
    lowbit = lowbit % 8;
    int highbyte = highbit / 8;
    highbit = highbit % 8;

    std::vector<unsigned char> bytes = bs.rep();
    int key;
    if (lowbyte == highbyte){
        key = ((bytes[lowbyte] >> (7 - highbit)) & (255 >> (8 - (highbit - lowbit + 1))));
    }
    else{
        int key1 = (bytes[lowbyte] & (255 >> (8 - (8 - lowbit)))) << (highbit + 1);
        int key2 = (bytes[highbyte] & (255 << (8 - (highbit + 1)))) >> (7 - highbit);
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
  uint32_t num = 1 << uint32_t(recon_settings.bq);
  std::vector<pnode_ptr> child_vec;

  for (uint32_t i=0; i < num; i++){
    pnode_ptr child_node = new_child(shared_from_this(), i);
    child_node->commit_node(true);
    child_vec.push_back(child_node);
  }
  //move elements into child nodes
  for (auto z : split_elements){
    bitset bs(z);

    int index = next(bs, depth);
    pnode_ptr child_node = child_vec[index];
    std::vector<NTL::ZZ_p> marray = child_node->add_element_array(z);
    child_node->insert(z, marray, bs, depth+1);
  }
}

pnode_ptr Pnode::parent(){
  std::string key = get_node_key();
  if (key.size()==0) return NULL;
  bitset parent_key(key);
  parent_key.resize(key.size() - recon_settings.bq);
  std::string parent_key_str = parent_key.to_string();
  pnode_ptr parent = get_node(parent_key_str);
  return parent;
}
 
void Pnode::remove(NTL::ZZ_p z, std::vector<NTL::ZZ_p> marray, bitset bs, int depth){
  pnode_ptr cur_node = shared_from_this();
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
            g_logger.log(Logger_level::CRITICAL, "Impossibile committare il nodo");
          }
          int child_index = cur_node->next(bs, depth);
          std::vector<pnode_ptr> child_vec;
          try{
              child_vec = cur_node->children();
          } catch (...){
            g_logger.log(Logger_level::CRITICAL, "Impossibile creare nodo figlio");
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
  if (marray.size() != get_points().size()) g_logger.log(Logger_level::CRITICAL, "marray and points do not have the same size");
  for (size_t i=0; i < marray.size(); i++){
      node_svalues[i] = node_svalues[i] * marray[i];
  }
}

void Pnode::insert(NTL::ZZ_p z, std::vector<NTL::ZZ_p> marray, bitset bs, int depth){
    pnode_ptr cur_node(shared_from_this());
    while(1){
        cur_node->update_svalues(marray, z);
        cur_node->set_num_elements(cur_node->get_num_elements() + 1);
        if (cur_node->is_leaf()){
            if (cur_node->get_node_elements().size() > recon_settings.split_threshold){
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
        cur_node->commit_node();
        
        int child_index = cur_node->next(bs, depth);
        cur_node = cur_node->children(child_index);

        depth += 1;
    }
}

MemTree::MemTree(){}
MemTree::~MemTree(){}

MemTree::MemTree(std::shared_ptr<RECON_DBManager> newdbm, std::vector<NTL::ZZ_p> new_points){
    dbm = newdbm;
    points = new_points;
    root = new_child(NULL, 0);
}

std::vector<NTL::ZZ_p> MemTree::get_points(){
    return points;
}

memnode_ptr MemTree::get_node(std::string key){
    std::queue<memnode_ptr> node_list;
    memnode_ptr cur_node = get_root();
    bool not_found = true;
    while (not_found){
        if (key == cur_node->get_node_key())
            not_found = false;
        if (cur_node->is_leaf()){
            if (node_list.empty())
                break;
        }else{
            for (auto n: cur_node->children())
                node_list.push(n);
        }
        cur_node = node_list.front();
        node_list.pop();
    }
    if (not_found)
        cur_node = NULL;
    return cur_node;
}

memnode_ptr Memnode::children(int cindex){
    return child_vec[cindex];
}

std::vector<memnode_ptr> Memnode::children(){
    return child_vec;
}

Memnode::Memnode(){
  std::vector<NTL::ZZ_p> svalues(recon_settings.num_samples);
  for (int i=0; i < recon_settings.num_samples; i++){
    NTL::ZZ_p z(1);
    svalues[i] = z;
  }
  set_node_svalues(svalues);
}

Memnode::~Memnode(){}

void Memnode::split(int depth){
  std::vector<NTL::ZZ_p> split_elements(get_node_elements());
  set_leaf(false);
  clear_node_elements();
  if ((get_node_elements().size() != 0) || (split_elements.size() == 0))
      g_logger.log(Logger_level::CRITICAL, "you did something wrong");

  //create child nodes
  uint32_t num = 1 << uint32_t(recon_settings.bq);

  for (uint32_t i=0; i < num; i++){
    memnode_ptr child_node = MemTree::new_child(shared_from_this(), i);
    child_vec.push_back(child_node);
  }
  //move elements into child nodes
  for (auto z : split_elements){
    bitset bs(z);

    int index = next(bs, depth);
    memnode_ptr child_node = child_vec[index];
    std::vector<NTL::ZZ_p> marray = child_node->MemTree::add_element_array(z);
    child_node->insert(z, marray, bs, depth+1);
  }
}

memnode_ptr Memnode::shared_from_this(){
    return std::static_pointer_cast<Memnode>(Pnode::shared_from_this());	
}

void Memnode::insert(NTL::ZZ_p z, std::vector<NTL::ZZ_p> marray, bitset bs, int depth){
    memnode_ptr cur_node = shared_from_this();
    while(1){
        cur_node->update_svalues(marray, z);
        cur_node->set_num_elements(cur_node->get_num_elements() + 1);
        if (cur_node->is_leaf()){
            if (cur_node->get_node_elements().size() > recon_settings.split_threshold){
                cur_node->split(depth);
            }
            else{
                std::ostringstream os;
                os << z;
                g_logger.log(Logger_level::DEBUG, "Inserting " + os.str() + " to node " + cur_node->get_node_key());
                cur_node->insert_element(z);
                return;
            }
        }
        int child_index = cur_node->next(bs, depth);
        cur_node = cur_node->children(child_index);

        depth += 1;
    }
}


memnode_ptr MemTree::new_child(memnode_ptr parent, int child_index){
  memnode_ptr n(new Memnode());
  n->set_leaf(true);
  bitset key;
  if (parent != NULL){
    std::string parent_key_string = parent->get_node_key();
    key = bitset(parent_key_string);
    int key_size = key.size();
    key.resize(key_size + recon_settings.bq);

    if (recon_settings.sks_bitstring == 0){
        for (int j=0; j<recon_settings.bq; j++){
           if (((1<<j)&child_index) == 0){
             key.clear(key_size + j);
           } else {
             key.set(key_size + j);
              }
        }
    }else{
        for (int j=recon_settings.bq - 1; j>=0; j--){
            if ((child_index & 1) == 1)
                key.set(key_size + j);
            else
                key.clear(key_size + j);
            child_index >>= 1;
        }
    }

  }
  std::string node_key = key.to_string();
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

void MemTree::commit_memtree(){
    std::queue<memnode_ptr> node_list;
    memnode_ptr cur_node = get_root();
    while(true){

        DBStruct::node n;
        n.key = cur_node->get_node_key();
        n.svalues = Utils::marshall_vec_zz_p(cur_node->get_node_svalues());
        n.num_elements = cur_node->get_num_elements();
        n.leaf = cur_node->is_leaf();
        n.elements = Utils::marshall_vec_zz_p(cur_node->get_node_elements());
        dbm->insert_node(n);

        if (cur_node->is_leaf()){
            if (node_list.empty())
                break;
        }else{
            for (auto n: cur_node->children())
                node_list.push(n);
        }
        cur_node = node_list.front();
        node_list.pop();
    }
}

void MemTree::insert(std::string hash){
    NTL::ZZ_p elem = Utils::hex_to_zz(hash);
    insert(elem);
}

void MemTree::insert(NTL::ZZ_p z){
    bitset bs(z);
    memnode_ptr root_node = get_root();
    std::vector<NTL::ZZ_p> marray = add_element_array(z);
    root_node->insert(z, marray, bs, 0);
}

memnode_ptr MemTree::get_root(){
    return root;
}
