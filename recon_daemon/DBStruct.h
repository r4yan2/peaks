#ifndef RECON_DBSTRUCT_H
#define RECON_DBSTRUCT_H

namespace RECON_DBStruct{

    struct node{
        std::string key;
        std::string svalues;
        int num_elements;
        bool leaf;
        std::string elements;
    };

}

#endif //RECON_DBSTRUCT_H
