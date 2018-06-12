#include <iostream>
#include "pTreeDB.h"

int main(){
 
  Ptree tree;
  if (tree.get_root() == NULL){
      std::cout << "tree init and root empty check: ok\n";
  }
  tree.create();
  std::cout << "root is leaf?\t" << tree.get_root()->is_leaf() << "\n";
  std::cout << "evaluation points: " << tree.get_points() << "\n";
  ZZ_p node_1(100);
  ZZ_p node_2(150);
  tree.insert(node_1);
  std::cout << "node inserted, num elements in root:\t" << tree.get_root()->get_num_elements()<< "\n";
  tree.insert(node_2);
  std::cout << "node inserted, num elements in root:\t" << tree.get_root()->get_num_elements()<< "\n";
  tree.remove(node_2);
  std::cout << "node removed, num elements in root:\t" << tree.get_root()->get_num_elements()<< "\n";
  std::cout << "root is still leaf?\t" << tree.get_root()->is_leaf() << "\n";
}

