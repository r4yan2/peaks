#include "recon_daemon.h"
#include <common/config.h>

namespace peaks{
namespace recon{

//PEAKS_PTREE_BUILDER
void build(po::variables_map &vm){
    
    std::cout << "Starting ptree builder" << std::endl;

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
    syslog(LOG_NOTICE, "Ptree builder is starting up!");
    if (RECON_Utils::create_folders(vm["tmp_folder"].as<std::string>()) != 0){
        std::cout << "Unable to create temporary directories!Exiting..." << std::endl;
        exit(1);
    }
    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(vm["P_SKS_STRING"].as<std::string>().c_str()));
    std::shared_ptr<Recon_memory_DBManager> dbm = std::make_shared<Recon_memory_DBManager>();
    int entries;
    std::vector<std::string> hashes;
    hashes = dbm->get_all_hash();
    entries = hashes.size();
    if (entries == 0){
        std::cout << "DB is empty! Continue anyway" << std::endl;
    }
    std::vector<NTL::ZZ_p> points = RECON_Utils::Zpoints(vm["num_samples"].as<int>());
    Ptree_config ptree_settings = {
        vm["mbar"].as<int>(),
        vm["bq"].as<int>(),
        vm["max_ptree_nodes"].as<int>(),
        vm["ptree_thresh_mult"].as<int>(),
        vm["num_samples"].as<int>(),
        points,
        vm["split_threshold"].as<int>(),
        vm["join_threshold"].as<int>(),
        vm["sks_bitstring"].as<int>(),
    };

    Ptree tree(dbm, ptree_settings);
    tree.create();
    int progress = 0;
    for (auto hash : hashes){
        tree.insert(hash);
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

    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(vm["P_SKS_STRING"].as<std::string>().c_str()));
    std::shared_ptr<Recon_mysql_DBManager> dbm = std::make_shared<Recon_mysql_DBManager>();
    std::vector<NTL::ZZ_p> points = RECON_Utils::Zpoints(vm["num_samples"].as<int>());
    const Ptree_config ptree_settings = {
        vm["mbar"].as<int>(),
        vm["bq"].as<int>(),
        vm["max_ptree_nodes"].as<int>(),
        vm["ptree_thresh_mult"].as<int>(),
        vm["num_samples"].as<int>(),
        points,
        vm["split_threshold"].as<int>(),
        vm["join_threshold"].as<int>(),
        vm["sks_bitstring"].as<int>(),
    };

    Ptree tree(dbm, ptree_settings);
    if (tree.create()){
        std::cout << "pTree appears to be empty...Exiting for your server satefy.\nIf you know what you're doing restart peaks to continue, this is a one-time check" << std::endl;
        exit(0);
    }

    const Connection_config conn_settings = {
        vm["mbar"].as<int>(),
        vm["bq"].as<int>(),
        vm["peaks_version"].as<std::string>(),
        vm["peaks_http_port"].as<int>(),
        vm["peaks_filters"].as<std::string>(),
        vm["max_read_len"].as<int>(),
        vm["async_timeout_sec"].as<int>(),
        vm["async_timeout_usec"].as<int>()
    };

    const Message_config msg_settings = {
        vm["max_read_len"].as<int>(),
        vm["P_SKS_STRING"].as<std::string>(),
        vm["sks_zp_bytes"].as<int>(),
        vm["max_request_queue_len"].as<int>(),
        vm["split_threshold"].as<int>()
    };

    const Recon_config peer_settings = {
        vm["membership_config"].as<std::string>(),
        vm["peaks_recon_port"].as<int>(),
        vm["request_chunk_size"].as<int>(),
        vm.count("dryrun"),
        vm["ignore_known_bug"].as<int>(),
        vm["hashquery_len"].as<int>(),
        vm["max_outstanding_recon_req"].as<int>(),
        vm["gossip_interval"].as<int>(),
        vm["max_recover_size"].as<int>()
    };

    server = vm.count("server-only");
    client = vm.count("client-only");
    peer = std::make_unique<Peer>(tree, peer_settings, conn_settings, msg_settings);
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
