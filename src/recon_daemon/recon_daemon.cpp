#include "recon_daemon.h"
#include <common/config.h>

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
    int entries;
    std::vector<std::string> hashes;
    hashes = dbm->get_all_hash();
    entries = hashes.size();
    if (entries == 0){
        std::cout << "DB is empty! Continue anyway" << std::endl;
    }
    Ptree ptree(dbm);
    ptree.create();
    int progress = 0;
    for (auto hash : hashes){
        ptree.insert(hash);
        progress += 1;
        if (progress%1000 == 0){
            printf ("\rProgress: %3d%%", (progress*100)/entries);
            fflush(stdout);
        }
    }

    std::cout << std::endl;
    std::cout << "Writing resulting ptree to DB!" << std::endl;
    dbm->commit_memtree();
    Utils::remove_directory_content(CONTEXT.get<std::string>("tmp_folder"));
    std::cout << "Inserted " << entries << " entry!" << std::endl; 
    closelog();
    exit(0);
}

void recon(){
    syslog(LOG_INFO, "Starting recon_daemon");
    std::unique_ptr<Peer> peer = std::make_unique<Peer>();
    if (CONTEXT.get<bool>("server-only"))
        peer->start_server();
    else if (CONTEXT.get<bool>("client-only"))
        peer->start_client();
    else
        peer->start();
}

}
}
