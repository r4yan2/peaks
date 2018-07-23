#include "peer.h"
#include "pTreeDB.h" 

using namespace NTL;

int main(int argc, char* argv[]){

    std::cout << "Starting recon_daemon" << std::endl;

    const char *MINUS_B = "-b";
    const char *MINUS_R = "-r";
    const char *MINUS_H = "-h";
    ZZ_p::init(conv<ZZ>(Recon_settings::P_SKS_STRING.c_str()));

    for (int i = 1; i < 2; i++){
        if(!strcmp(argv[i], MINUS_H)){
            std::cout << "Parameters:" << std::endl;
            std::cout << "-b: build prefix tree" << std::endl;
            std::cout << "-r: start recon" << std::endl;
        }
        else if(!strcmp(argv[i], MINUS_B)){
            const std::vector<ZZ_p> points = Utils::Zpoints(num_samples);
            std::shared_ptr<RECON_DBManager> dbm = std::make_shared<RECON_DBManager>(); 
            std::vector<std::string> hashes = dbm->get_all_hash();
            Ptree tree(dbm, points);
            tree.create();
            tree.populate(hashes);
            std::cout << "Inserted " << hashes.size() << " entry!" << std::endl; 
        }
        else if(!strcmp(argv[i], MINUS_R)){
            const std::vector<ZZ_p> points = Utils::Zpoints(num_samples);
            std::shared_ptr<RECON_DBManager> dbm = std::make_shared<RECON_DBManager>(); 
            Ptree tree(dbm, points);
            tree.create();
            Peer peer = Peer(tree);
            peer.start();
        }
    }
    exit(0);
}
