#include "recon_daemon.h"
#include <common/config.h>
#include <memory>

namespace peaks{
namespace recon{

//PEAKS_PTREE_BUILDER
void build(){
    std::cout << "Starting ptree builder" << std::endl;
    syslog(LOG_NOTICE, "Ptree builder is starting up!");
    if (Utils::create_folders(CONTEXT.get<std::string>("tmp_folder")) != 0){
        std::cout << "Unable to create temporary directories!Exiting..." << std::endl;
        exit(1);
    }
    std::shared_ptr<Recon_memory_DBManager> dbm = std::make_shared<Recon_memory_DBManager>();

    PTREE.set_db(dbm);
    PTREE.create();

    int entries = 0;
    int progress = 0;
    int limit = 50000;
    int offset = 0;
    int total = dbm->get_hash_count();
    std::vector<std::string> hashes;
    do {
        std::shared_ptr<DBResult> res = dbm->get_all_hash_iterator(limit, offset);
        offset += limit;
        entries = res->size();
        if (progress == 0 && entries == 0){
            std::cout << "DB is empty! Storing an empty prefix tree" << std::endl;
        }
        std::string hash = "";
        while((hash = dbm->get_hash_from_results(res)) != ""){
            PTREE.insert(hash);
            progress += 1;
            if (progress%1000 == 0){
                printf ("\rProgress: %3d%%", (progress*100)/total);
                fflush(stdout);
            }
        }
    } while (progress < total);

    std::cout << std::endl;
    dbm->write_memtree_csv();
    if (CONTEXT.get<bool>("csv-only", false)){
        std::cout << "Not Writing resulting ptree as requested" << std::endl;
        exit(0);
    }
    std::cout << "Writing resulting ptree to DB!" << std::endl;
    dbm->commit_memtree();
    std::cout << "Inserted " << entries << " entry!" << std::endl; 
    closelog();
    exit(0);
}

void recon(){
    syslog(LOG_INFO, "Starting recon_daemon");
    std::unique_ptr<PeerManager> peermanager = std::make_unique<PeerManager>();
    if (CONTEXT.get<bool>("server-only"))
        peermanager->start_server();
    else if (CONTEXT.get<bool>("client-only"))
        peermanager->start_client();
    else
        peermanager->start();
}

}
}
