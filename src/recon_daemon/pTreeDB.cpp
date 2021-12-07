#include "pTreeDB.h"
#include <common/config.h>


namespace peaks{
namespace recon{

Ptree::Ptree():
    root(NULL),
    dbm(std::make_shared<Recon_mysql_DBManager>())
{
    Bitset bs(0);
    try{
        root = node(bs);
    }catch(std::runtime_error &e){
        //expected, tree need to be initialized explicitly when empty
    }
}

Ptree& Ptree::ptree(){
    static Ptree instance;
    return instance;
}

Ptree::~Ptree(){}

void Ptree::set_db(std::shared_ptr<RECON_DBManager> dbm_){
    dbm = dbm_;
}

pnode_ptr Ptree::get_root(){
    return root;
}

std::vector<NTL::ZZ_p> Ptree::add_element_array(const NTL::ZZ_p &z){
    std::vector<NTL::ZZ_p> marray(CONTEXT.treesettings.num_samples);
    for(size_t i=0; i<CONTEXT.treesettings.num_samples; i++){
        marray[i] = CONTEXT.treesettings.points[i] - z;
        if (marray[i] == 0){
            syslog(LOG_CRIT, "marray has a zero element!");
            throw std::runtime_error("marray has a zero element");
        }
    }
    return marray;
}

std::vector<NTL::ZZ_p> Ptree::delete_element_array(const NTL::ZZ_p &z){
    std::vector<NTL::ZZ_p> marray(CONTEXT.treesettings.num_samples);
    for(size_t i=0; i < CONTEXT.treesettings.num_samples; i++){
        marray[i] = inv(CONTEXT.treesettings.points[i] - z);
    }
    return marray;
}

bool Ptree::create(){
    root = new_child(Bitset(), -1);
    root->commit_node(true);
}

int Ptree::get_mbar(){
    return CONTEXT.treesettings.mbar;
}

int Ptree::get_bq(){
    return CONTEXT.treesettings.bq;
}

size_t Ptree::get_num_samples(){
    return CONTEXT.treesettings.num_samples;
}

int Ptree::get_max_ptree_nodes(){
    return CONTEXT.treesettings.max_ptree_nodes;
}

int Ptree::get_ptree_thresh_mult(){
    return CONTEXT.treesettings.ptree_thresh_mult;
}

std::vector<NTL::ZZ_p> Ptree::get_points(){
    return CONTEXT.treesettings.points;
}

unsigned int Ptree::get_split_threshold(){
    return CONTEXT.treesettings.split_threshold;
}

unsigned int Ptree::get_join_threshold(){
    return CONTEXT.treesettings.join_threshold;
}

int Ptree::get_sks_bitstring(){
    return CONTEXT.treesettings.sks_bitstring;
}
pnode_ptr Ptree::get_node(const Bitset& key){
    DBStruct::node n = dbm->get_node(key);
    pnode_ptr nd (new Pnode(this));
    nd->set_node_key(key);
    nd->set_node_svalues(n.svalues);
    nd->set_num_elements(n.num_elements);
    nd->set_leaf(n.leaf);
    nd->set_node_elements(n.elements);
    return nd;
}

bool Ptree::has_key(const std::string &key){
    return dbm->check_key(key);
}

void Ptree::insert(const std::string &hash){
    NTL::ZZ_p elem = Utils::hex_to_zz(hash);
    insert(elem);
}

void Ptree::insert(const NTL::ZZ_p &z){
    Bitset bs(z);
    pnode_ptr root_node = get_root();
    std::vector<NTL::ZZ_p> marray = add_element_array(z);
    root_node->insert(z, marray, bs, 0);
}

void Ptree::update(const std::vector<std::string> &hash_to_insert){

    std::vector<std::string> hash_to_remove = dbm->fetch_removed_elements();
    for (auto hash: hash_to_remove){
        syslog(LOG_DEBUG, "removing %s from ptree", hash.c_str());
        remove(hash);
    }
    for (auto hash: hash_to_insert){
        syslog(LOG_DEBUG, "inserting %s into ptree", hash.c_str());
        insert(hash);
    }
    syslog(LOG_DEBUG, "removed %d hashes from the ptree", int(hash_to_remove.size()));
    syslog(LOG_DEBUG, "inserted %d hashes into the ptree", int(hash_to_insert.size()));
}

Bitset generate_child_key(const Bitset& parent_key, int bq, int c_idx){
    Bitset child_key(parent_key);
    child_key.resize(child_key.size() + bq);

    /*
     * Feel more correct this way but it does not work
    for (int j=0; j<bq; j++)
        if ((1<<(bq-1-j)) & c_idx) child_key.set(-bq+j);
        */
    for (int j=0; j<bq; j++)
        if ((1<<(bq-1-j)) & c_idx) child_key.set(0-j-1);

    return child_key;
}

pnode_ptr Ptree::new_child(const Bitset& parent_key, int child_index){
    pnode_ptr n (new Pnode(this));
    n->set_leaf(true);
    n->set_num_elements(0);
    Bitset key;
    if (child_index >= 0){
        key = generate_child_key(
                parent_key,
                get_bq(),
                child_index);
    }
    n->set_node_key(key);
    std::vector<NTL::ZZ_p> svalues(CONTEXT.treesettings.num_samples);
    for (size_t i=0; i < CONTEXT.treesettings.num_samples; i++){
        NTL::ZZ_p z(1);
        svalues[i] = z;
    }
    n->set_node_svalues(svalues);
    return n;
}

pnode_ptr Ptree::node(Bitset &key){
    Bitset target_key;
    if (key.size() != 0)
        target_key = key;
    pnode_ptr n;
    while(1){
        try{
            n = get_node(target_key);
            break;
        } catch (std::exception &e){
            syslog(LOG_DEBUG, "Search for node %s failed -- %s -- searching for the nearest parent...", Bitset::to_string(target_key).c_str(), e.what());
        }
        if (key.size() == 0)
            throw std::runtime_error("root not found");

        target_key.resize(target_key.size() - CONTEXT.treesettings.bq);
    }
    return n;
}

void Ptree::remove(const NTL::ZZ_p &z){
    Bitset bs(z);
    pnode_ptr root = get_root();
    std::vector<NTL::ZZ_p> marray = delete_element_array(z);
    root->remove(z, marray, bs, 0);
}

void Ptree::remove(const std::string &hash){
    NTL::ZZ_p elem = Utils::hex_to_zz(hash);
    remove(elem);
}

Pnode::Pnode(){}

Pnode::Pnode(const Pnode & n):
    tree(n.tree),
    node_key(n.get_node_key()),
    node_svalues(n.get_node_svalues()),
    leaf(n.is_leaf()),
    num_elements(n.get_num_elements()),
    node_elements(n.get_node_elements())
{}

Pnode::Pnode(Ptree* pointer):
    tree(pointer),
    node_key(),
    leaf(true),
    num_elements()
{}

Pnode::~Pnode(){}

int Pnode::get_num_elements() const{
    return num_elements;
}

std::vector<NTL::ZZ_p> Pnode::get_node_svalues() const{
    return node_svalues;
}

Bitset Pnode::get_node_key() const {
    return node_key;
}

bool Pnode::is_leaf() const {
    return leaf;
}

std::vector<NTL::ZZ_p> Pnode::get_node_elements() const {
    return node_elements;
}

void Pnode::set_node_key(const Bitset& new_key){
    node_key = new_key;
}

void Pnode::set_num_elements(int num){
    num_elements = num;
}

void Pnode::set_node_svalues(const std::vector<NTL::ZZ_p> &new_values){
    node_svalues = new_values;
}

void Pnode::set_node_elements(const std::vector<NTL::ZZ_p> &new_elements){
    node_elements = new_elements;
}

void Pnode::set_leaf(bool new_leaf){
    leaf = new_leaf;
}

pnode_ptr Pnode::children(int c_index){
    if (is_leaf())
        throw std::runtime_error("requested child of leaf node");
    Bitset key = get_node_key();
    Bitset child_key = generate_child_key(key, tree->get_bq(), c_index);
    pnode_ptr child = tree->node(child_key);
    return child;
}

std::vector<pnode_ptr> Pnode::children(){
    std::vector<pnode_ptr> result;
    if (is_leaf()){
        return result;
    }
    int num_children = 1 << tree->get_bq();

    for (int i=0; i<num_children; i++)
        result.push_back(children(i));
    return result;
}

void Pnode::clear_node_elements(){
    node_elements.clear();
}

void Pnode::commit_node(bool newnode){
    DBStruct::node n;
    n.key = node_key.blob();
    n.key_size = node_key.size();
    n.svalues = get_node_svalues();
    n.num_elements = num_elements;
    n.leaf = leaf;
    n.elements = get_node_elements();
    if (newnode)
        tree->db_insert(n);
    else
        tree->db_update(n);
}

void Pnode::delete_node(){
    tree->db_delete(node_key);
}

void Ptree::db_insert(DBStruct::node &n){
    dbm->insert_node(n);
}

void Ptree::db_update(DBStruct::node &n){
    dbm->update_node(n);
}

void Ptree::db_delete(const Bitset& node_key){
    dbm->delete_node(node_key);
}

void Pnode::delete_elements(){
    node_elements.clear();
    commit_node();
}

void Pnode::delete_element(const NTL::ZZ_p &elem){
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
        std::vector<pnode_ptr> children_vec = children();
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
        throw std::runtime_error("No child nodes available!");
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

void Pnode::insert_element(const NTL::ZZ_p &elem){
    node_elements.push_back(elem);
}

int Pnode::next(const Bitset &bs, int depth){
    return next_peaks(bs, depth);
}

int Pnode::next_peaks(const Bitset &bs, int depth){
    int bq = tree->get_bq();
    int start = depth * bq;
    int end = start + bq;
    return bs.slice(start, end).to_int();
}

int Pnode::next_hockeypuck(const Bitset &bs, int depth){
    if (is_leaf()){
        throw std::runtime_error("Requested child of a leaf node");
    }
    int childIndex = 0;
    for (int i=0; i<tree->get_bq(); i++){
        auto mask = 1 << uint32_t(i);
        if (bs.test((depth*tree->get_bq())+i)) childIndex |= mask;
    }
    return childIndex;
}

int Pnode::next_sks(const Bitset &bs, int depth){
    int lowbit = depth * tree->get_bq();
    int highbit = lowbit + tree->get_bq() - 1;
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
        syslog(LOG_WARNING, "you did something wrong");

    commit_node();

    //create child nodes
    uint32_t num = 1 << uint32_t(tree->get_bq());
    std::vector<pnode_ptr> child_vec;

    for (uint32_t i=0; i < num; i++){
        pnode_ptr child_node = tree->new_child(get_node_key(), i);
        child_node->commit_node(true);
        child_vec.push_back(child_node);
    }
    //move elements into child nodes
    for (auto z : split_elements){
        Bitset bs(z);

        int index = next(bs, depth);
        pnode_ptr child_node = child_vec[index];
        std::vector<NTL::ZZ_p> marray = tree->add_element_array(z);
        child_node->insert(z, marray, bs, depth+1);
    }
}
pnode_ptr Pnode::parent(){
    Bitset key = get_node_key();
    if (key.size()==0) throw std::runtime_error("requested parent of root node");
    Bitset parent_key(key);
    parent_key.resize(key.size() - tree->get_bq());
    return tree->get_node(parent_key);
}

void Pnode::remove(const NTL::ZZ_p &z, const std::vector<NTL::ZZ_p> &marray, const Bitset &bs, int depth){
    pnode_ptr cur_node = getReference();
    while(1){
        cur_node->update_svalues(marray);
        cur_node->set_num_elements(cur_node->get_num_elements() - 1);
        if (cur_node->is_leaf()){
            break;
        } else{
            if (cur_node->get_num_elements() <= tree->get_join_threshold()){
                try{
                    cur_node->join();
                } catch (std::exception &e){
                    syslog(LOG_WARNING, "Caught exception while joining node");
                }
                break;
            }
            else {
                try{
                    cur_node->commit_node();
                }
                catch (std::exception &e){
                    syslog(LOG_WARNING, "Node commit failed because of %s", e.what());
                }
                int child_index = cur_node->next(bs, depth);
                std::vector<pnode_ptr> child_vec;
                try{
                    child_vec = cur_node->children();
                } catch (std::exception &e){
                    syslog(LOG_CRIT, "Error during child node recover, error: %s", e.what());
                }
                cur_node = child_vec[child_index];
                depth++;
            }
        }
    }
    try{
        cur_node->delete_element(z);
    } catch (std::exception &e){
        syslog(LOG_WARNING, "Error during elements delete, error: %s", e.what());
    }
    cur_node->commit_node();
}

void Pnode::update_svalues(const std::vector<NTL::ZZ_p> &marray){
    if (marray.size() != node_svalues.size()) 
        syslog(LOG_CRIT, "marray and svalues do not have the same size (%d) and (%d) respectively", (int)marray.size(), (int) node_svalues.size() );
    for (size_t i=0; i < marray.size(); i++){
        node_svalues[i] = node_svalues[i] * marray[i];
    }
}

pnode_ptr Pnode::getReference(){
    return shared_from_this();
}

void Pnode::insert(const NTL::ZZ_p &z, const std::vector<NTL::ZZ_p> &marray, const Bitset &bs, int depth){
    pnode_ptr cur_node = getReference();
    while(1){
        cur_node->update_svalues(marray);
        cur_node->set_num_elements(cur_node->get_num_elements() + 1);
        if (cur_node -> is_leaf()){

            if (cur_node -> get_num_elements() > tree->get_split_threshold()){
                cur_node -> split(depth);
            }
            else {
                cur_node -> insert_element(z);
                cur_node -> commit_node();
                return;
            }
        }
        cur_node -> commit_node();

        int child_index = cur_node -> next(bs, depth);
        cur_node = cur_node->children(child_index);

        depth += 1;
    }
}

}
}
