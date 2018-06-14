#include <iostream>
#include "pTreeDB.h"

int main(){
  const char* P_SKS_STRING = "530512889551602322505127520352579437339";
  const ZZ P_SKS = conv<ZZ>(P_SKS_STRING);
  ZZ_p::init(P_SKS); 
  const Vec<ZZ_p> points = recon::Utils::Zpoints(num_samples);
  std::shared_ptr<DBManager> dbm = std::make_shared<DBManager>(); 
  Ptree tree(dbm, points);
  tree.create();
  tree.populate();
}

