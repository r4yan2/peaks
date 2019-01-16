#include "recon_daemon.h"

//PEAKS_PTREE_BUILDER
void build(po::variables_map &vm){
    
    std::cout << "Starting ptree builder" << std::endl;
    openlog("peaks_recon_daemon", LOG_PID, LOG_USER);
    if (vm.count("debug")){
        std::cout << "debug output" << std::endl;
        setlogmask(LOG_UPTO(LOG_DEBUG));
    }
    else
        setlogmask (LOG_UPTO (LOG_INFO));
    syslog(LOG_NOTICE, "Ptree builder is starting up!");
    if (RECON_Utils::create_folders(vm["recon_tmp_folder"].as<std::string>()) != 0){
        std::cout << "Unable to create temporary directories!Exiting..." << std::endl;
        exit(1);
    }
    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(vm["P_SKS_STRING"].as<std::string>().c_str()));
    Recon_DBConfig db_settings = {
        vm["db_host"].as<std::string>(),
        vm["db_user"].as<std::string>(),
        vm["db_password"].as<std::string>(),
        vm["db_database"].as<std::string>(),
        vm["recon_tmp_folder"].as<std::string>()
    };

    std::shared_ptr<RECON_DBManager> dbm = std::make_shared<RECON_DBManager>(db_settings);
    int entries;
    std::vector<std::string> hashes;
    hashes = dbm->get_all_hash();
    entries = hashes.size();
    if (entries == 0){
        std::cout << "DB is empty! Aborting..." << std::endl;
        exit(0);
    }
    Ptree_config ptree_settings = {
        vm["mbar"].as<int>(),
        vm["bq"].as<int>(),
        vm["max_ptree_nodes"].as<int>(),
        vm["ptree_thresh_mult"].as<int>(),
        vm["num_samples"].as<int>(),
        Zpoints(vm["num_samples"].as<int>()),
        vm["split_threshold"].as<int>(),
        vm["join_threshold"].as<int>(),
        vm["sks_bitstring"].as<int>()
    };

    Memtree tree(dbm, ptree_settings);
    tree.init_root();
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
    dbm->lockTables();
    tree.commit_memtree();
    dbm->unlockTables();
    DUMP_Utils::remove_directory_content(vm["recon_tmp_folder"].as<std::string>());
    std::cout << "Inserted " << entries << " entry!" << std::endl; 
    closelog();
    exit(0);
}

//PEAKS_RECON_DAEMON settings;
void recon(po::variables_map &vm){

    std::cout << "Starting recon_daemon" << std::endl;
    openlog("peaks_recon_daemon", LOG_PID, LOG_USER);
    if (vm.count("debug")){
        std::cout << "debug output" << std::endl;
        setlogmask(LOG_UPTO(LOG_DEBUG));
    }
    else
        setlogmask (LOG_UPTO (LOG_INFO));

    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(vm["P_SKS_STRING"].as<std::string>().c_str()));
    const std::vector<NTL::ZZ_p> points = Zpoints(vm["num_samples"].as<int>());
    Recon_DBConfig db_settings = {
        vm["db_host"].as<std::string>(),
        vm["db_user"].as<std::string>(),
        vm["db_password"].as<std::string>(),
        vm["db_database"].as<std::string>(),
        vm["recon_tmp_folder"].as<std::string>()
    };
    std::shared_ptr<RECON_DBManager> dbm = std::make_shared<RECON_DBManager>(db_settings);
    Ptree_config ptree_settings = {
        vm["mbar"].as<int>(),
        vm["bq"].as<int>(),
        vm["max_ptree_nodes"].as<int>(),
        vm["ptree_thresh_mult"].as<int>(),
        vm["num_samples"].as<int>(),
        points,
        vm["split_threshold"].as<int>(),
        vm["join_threshold"].as<int>(),
        vm["sks_bitstring"].as<int>()
    };

    Ptree tree(dbm, ptree_settings);
    if (tree.create()){
        std::cout << "pTree appears to be empty...Exiting for your server satefy.\nIf you know what you're doing restart peaks to continue, this is a one-time check" << std::endl;
        exit(0);
    }

    Connection_config conn_settings = {
        vm["mbar"].as<int>(),
        vm["bq"].as<int>(),
        vm["peaks_version"].as<std::string>(),
        vm["peaks_http_port"].as<int>(),
        vm["peaks_filters"].as<std::string>(),
        vm["max_read_len"].as<int>(),
        vm["async_timeout_sec"].as<int>(),
        vm["async_timeout_usec"].as<int>()
    };


    Message_config msg_settings = {
        vm["max_read_len"].as<int>(),
        vm["P_SKS_STRING"].as<std::string>(),
        vm["sks_zp_bytes"].as<int>(),
        vm["max_request_queue_len"].as<int>(),
        vm["split_threshold"].as<int>()
    };

    Recon_config peer_settings = {
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
    ReconImporter di = ReconImporter(vm);
    Peer peer = Peer(tree, peer_settings, conn_settings, di, msg_settings);
    if (vm.count("server-only"))
        peer.start_server();
    else if (vm.count("client-only"))
        peer.start_client();
    else
        peer.start();
    exit(0);
}

std::vector<NTL::ZZ_p> Zpoints(int num_samples){
  std::vector<NTL::ZZ_p> points(num_samples);
  for (int i=0; i<num_samples; i++){
    int val = ((i + 1) / 2) * ((i % 2 == 0) ? 1 : (-1));
    NTL::ZZ_p tmp(val);
    points[i]=tmp;
  }
  return points;
}

