#ifndef PTREE_SETTINGS_H
#define PTREE_SETTINGS_H

namespace PTree_settings{
  
    const int mbar = 5;
    const int bq = 2; //bitquantum
    const int max_ptree_nodes = 1000;
    const int ptree_thresh_mult = 10;
    const int num_samples = mbar + 1;
    const int split_threshold = ptree_thresh_mult * mbar;
    const int join_threshold = split_threshold/2;
}

#endif
