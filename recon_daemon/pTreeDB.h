#ifndef RECON_PTREEDB_H
#define RECON_PTREEDB_H

#include "DBManager.h"
#include "Recon_settings.h"
#include "Utils.h"
#include <syslog.h>
#include <iostream>
#include <stdexcept>
#include "Bitset.h"
#include "myset.h"
#include <queue>
#include <memory>

typedef Bitset bitset;

class Pnode;
class Ptree;

typedef std::shared_ptr<Pnode> pnode_ptr;
//typedef std::shared_ptr<Ptree> ptree_ptr;
typedef Ptree* ptree_ptr;

bitset generate_child_key(const bitset&, int, int);

/** Node class, inherit bunch of methods from Ptree and inherit the possibility to share 'this' reference with new nodes
 */
class Pnode: public std::enable_shared_from_this<Pnode>{
    
private:
    Ptree* tree;

    /** node key is the identifier of the node */
    bitset node_key;

    /** node svalues are used to perform linear interpolation upon ReconRequestPoly */
    std::vector<NTL::ZZ_p> node_svalues;

    /** leaf is a flag to check if the node is a leaf node in the ptree or an intermediate */
    bool leaf;

    /** num_elements contains the number of elements under such nodes, which includes the count of child nodes */
    int num_elements;

    /** node_elements contains the elements for this node (only for leaf node, after reaching the elements threshold, split is called and elements are trasferred to child nodes) */
    std::vector<NTL::ZZ_p> node_elements;

public:
    Pnode();

    /** like ptree nodes are initialized keeping a reference to the database manager */
    Pnode(Ptree* pointer);
    ~Pnode();
    Pnode(const Pnode & n);

    pnode_ptr getReference();
    
    /** setter for node key
     * @param key new_key for the node (this is setted once upon node creating)
     */
    void set_node_key(const bitset& key);

    /** setter for svalues
     * @param svalues new svalues for the node
     */
    void set_node_svalues(const std::vector<NTL::ZZ_p> &svalues);

    /** setter for num elements, the only purpose of this method is doing a +1, so it could be replaced with an appropriate method
     * @param num new elements number
     */
    void set_num_elements(int num);

    /** setter for leaf, used during split to make a leaf node, and during join to make a node leaf
     * @param b new value of leafness
     */
    void set_leaf(bool b);

    /** setter for node_elements
     * @param elements new vector elements for the node
     */
    void set_node_elements(const std::vector<NTL::ZZ_p> &elements);
    
    /** getter for node key
     * @return key as string
     */
    bitset get_node_key() const;

    /** getter for the node svalues
     * @return std vector of node svalues
     */
    std::vector<NTL::ZZ_p> get_node_svalues() const;
    
    /** get the number of elements under the given node */
    int get_num_elements() const;

    /** check if node is leaf */
    bool is_leaf() const;

    /** get the elements stored in node */
    std::vector<NTL::ZZ_p> get_node_elements() const;

    void clear_node_elements();
    
    /** fetch the children of current node */
    std::vector<pnode_ptr> children();

    /** fetch a specific children of current node */
    pnode_ptr children(int c_index);

    /** commit node to DB */
    void commit_node(bool newnode = false);

    /** delete node from ptree */
    void delete_node();
    void delete_elements();
    void delete_element(const NTL::ZZ_p &elem);
    std::vector<NTL::ZZ_p> elements();

    /** join this node with parent when the threshold is reached */
    void join();

    /** insert elements into ptree (actual insertion)
     * @param z elem to insert
     * @param marray array used to update svalues
     * @param bs, used to iterate in case the current node is full
     * @param depth current depth at which insert is performed
     */
    void insert(const NTL::ZZ_p &z, const std::vector<NTL::ZZ_p> &marray, const bitset &bs, int depth);

    /** push element into node_elements vector
     * @param elem new element to push back into vector
     */
    void insert_element(const NTL::ZZ_p &elem);

    /** fetch next node in which element has to be inserted 
     * @param bs bitstring identifier of the parent node
     * @param depth current search depth of the ptree
     * @return index of the child node
     * */
    int next(const bitset &bs, int depth);

    /** helper for next (calculated as sks would) */
    int next_sks(const bitset &bs, int depth);
    /** helper for next (calculated as hockeypuck would) */
    int next_hockeypuck(const bitset &bs, int depth);
    int next_peaks(const bitset &bs, int depth);

    /** get the pointer to the parent node 
     * @return reference to parent node
     */
    pnode_ptr parent();

    /** remove element from the node(actual remove operation)
     * @param z elem to insert
     * @param marray array used to update svalues
     * @param bs, used to iterate in case the current node is full
     */
    void remove(const NTL::ZZ_p &z, const std::vector<NTL::ZZ_p> &marray, const bitset &bs, int depth);

    /** split a node when the threshold is reached
     * @param depth current depth
     */
    void split(int depth);

    /** update the svalues 
     * @param marray used to calculate new svalues
     */
    void update_svalues(const std::vector<NTL::ZZ_p> &marray);
};


/** Holds the current ptree reference.
 * The ptree reference is initialized in main,
 * but since uses the DB to recover nodes,
 * it can be used everywhere, it does not
 * hold any particular data, just the root, and the 
 * refernce to the database manager
 */
class Ptree{
private:
    /** Pointer to the root node */
    pnode_ptr root;

    /** Pointer to the database manager */
    std::shared_ptr<RECON_DBManager> dbm;
  
    /** Settings */
    Ptree_config settings;
public:
    Ptree();

	/** Constructor for ptree
     * @param dbp Databse manager pointer, will be passed to created nodes
     */
    Ptree(std::shared_ptr<RECON_DBManager> dbp, const Ptree_config &settings_);
    ~Ptree();
    int get_mbar();
    int get_bq();
    size_t get_num_samples();
    int get_max_ptree_nodes();
    int get_ptree_thresh_mult();
    std::vector<NTL::ZZ_p> get_points();
    unsigned int get_split_threshold();
    unsigned int get_join_threshold();
    int get_sks_bitstring();

    void db_insert(RECON_DBStruct::node &n);
    void db_update(RECON_DBStruct::node &n);
    void db_delete(const bitset& node_key);

    /** Getter for root node
     * @return pointer to root node
     */
    pnode_ptr get_root();
    
    /** Calculate marray for given element, with the default interpolation points
     * @param z new element of the tree
     * @return calculated vector
     */
    std::vector<NTL::ZZ_p> add_element_array(const NTL::ZZ_p &z);

    Ptree_config get_settings();
    /** Calculate marray after deletion of given element
     * @param z element for which subtraction has to be made
     * @resulting array to subtract
     */
    std::vector<NTL::ZZ_p> delete_element_array(const NTL::ZZ_p &z);
    
    /** Create the ptree, by initializing root if a root node cannot be found in database
     * @return true if this function create a root node, false otherwise
     */
    bool create();

    /** search for a specific node in the DB
     * @param key key of the node to search
     * @return pointer to fetched node if found
     */
    pnode_ptr get_node(const bitset& key);

    /** check if a certain key is in the DB
     * @param key key to check
     * @return true if found, false otherwise
     */
    bool has_key(const std::string &key);

    /** insert ZZ into the prefix-tree 
     * @param z new NTL:ZZ_p number to insert in the tree
     */
    void insert(const NTL::ZZ_p &z);

    /** insert an hash into the prefix-tree
     * @param hash md5hash to insert as new element of the tree
     */
    void insert(const std::string &hash);

    /** generate a new child for the given parent
     * @param parent pointer to the parent node (usually this method is called by the parent, so it's a pointer to this, which need to be wrapped into a smart pointer, thus the need to inherit from std::enable_shared_from_this
     * @param child_index is the index of the child with respect to the other child (max index = 2^mbar)
     * @return pointer to the new child
     */
    pnode_ptr new_child(const bitset& parent_key, int child_index);

    /** search for the nearest parent of the given key, up to the root
     * @param key key to search in the tree
     * @return pointer to the found node
     */
    pnode_ptr node(bitset &key);

    /** remove a node from the ptree
     * @param z node to remove
     */
    void remove(const NTL::ZZ_p &z);
    
    /** remove an hash into the prefix-tree
     * @param hash md5hash to remove
     */
    void remove(const std::string &hash);

    void update(const std::vector<std::string> &hashes);
};

#endif //RECON_PTREEDB_H
