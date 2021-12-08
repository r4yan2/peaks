#include "recon_daemon.h"
#include <common/config.h>

namespace peaks{
namespace recon{

//PEAKS_PTREE_BUILDER
void build(po::variables_map &vm){
    std::cout << "Starting ptree builder" << std::endl;
    syslog(LOG_NOTICE, "Ptree builder is starting up!");
    if (Utils::create_folders(vm["tmp_folder"].as<std::string>()) != 0){
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
    PTREE.set_db(dbm);
    PTREE.create();
    int progress = 0;
    for (auto hash : hashes){
        PTREE.insert(hash);
        progress += 1;
        if (progress%1000 == 0){
            printf ("\rProgress: %3d%%", (progress*100)/entries);
            fflush(stdout);
        }
    }

    std::cout << std::endl;
    std::cout << "Writing resulting ptree to DB!" << std::endl;
    dbm->commit_memtree();
    Utils::remove_directory_content(vm["tmp_folder"].as<std::string>());
    std::cout << "Inserted " << entries << " entry!" << std::endl; 
    closelog();
    exit(0);
}

Recon::Recon(po::variables_map &vm){

    std::cout << "Starting recon_daemon" << std::endl;
    int log_option;
    int log_upto;

    if (vm.count("stdout")){
        std::cout << "logging to stdout" << std::endl;
        log_option = LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID;
    }
    else{
        log_option = LOG_PID;
    }
    if (vm.count("debug")){
        std::cout << "debug output" << std::endl;
        log_upto = LOG_UPTO(LOG_DEBUG);
    }
    else{
        log_upto = LOG_UPTO(LOG_INFO); 
    }

    openlog("peaks_recon_daemon", log_option, LOG_USER);
    setlogmask(log_upto);

    std::shared_ptr<Recon_mysql_DBManager> dbm = std::make_shared<Recon_mysql_DBManager>();
    std::vector<NTL::ZZ_p> points = Utils::Zpoints(vm["num_samples"].as<int>());

    server = vm.count("server-only");
    client = vm.count("client-only");
    peer = std::make_unique<Peer>();
}

void Recon::run(){
    if (server)
        peer->start_server();
    else if (client)
        peer->start_client();
    else
        peer->start();
}

}
}
