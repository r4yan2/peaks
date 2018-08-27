#include "peer.h"
#include "pTreeDB.h" 
#include "logger.h"
#include <getopt.h>
#include "Recon_settings.h"
#include <fstream>

Configtype recon_settings;

void help();
void parse_config(std::string filename);
void build();
void run();
std::vector<NTL::ZZ_p> parse_custom_hash_file();

int main(int argc, char* argv[]){

    const char * s_opt = "hdbc:";

    /*
     * TODO setup long opt
    static struct option long_options[] =
    {
        {"help", no_argument, 0, 0},
        {"debug", no_argument, &verbose, 1},
        {"command", required_argument, NULL, 0},
        {NULL, 0, NULL, 0}
    };
    */
    int c;
    std::string filename = "recon_config";
    bool verbose = false;
    bool build_ptree = false;

    while ((c = getopt(argc, argv, s_opt)) != -1)
    {
        switch (c)
        {
             case 'd':
                 verbose = true;
                 break;
             case 'c':
                 filename = optarg;
                 break;
             case 'b':
                 build_ptree = true;
                 break;
             case 'h':
             case '?':
             default:
                 help();
        }
    }
    parse_config(filename);
    g_logger.init(verbose);
    if (build_ptree)
        build();
    run();
}

void help(){

    std::cout << "Usage:" << std::endl;
    std::cout << "recon_daemon [-d] [-c configfile] [-b]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "-d enable more verbose log" << std::endl;
    std::cout << "-c receive as argument the path of the config file" << std::endl;
    std::cout << "-b only build the prefix-tree" << std::endl;
    std::cout << std::endl;
    std::cout << "For the first run, start peaks with -b, which will init the prefix tree, then start again without -b to start reconing" << std::endl;
    std::cout << std::endl;
    exit(0);
}

void parse_config(std::string filename){
    std::ifstream cFile (filename);
    if (cFile.is_open())
    {
        std::string line;
        while(getline(cFile, line)){
            line.erase(remove_if(line.begin(), line.end(), isspace),
                                 line.end());
            if(line[0] == '#' || line.empty())
                continue;
            auto delimiterPos = line.find("=");
            auto name = line.substr(0, delimiterPos);
            auto value = line.substr(delimiterPos + 1);
            if (name == "mbar")
                recon_settings.mbar = std::stoi(value);
            else if (name == "bq")
                recon_settings.bq = std::stoi(value);
            else if (name == "max_ptree_nodes")
                recon_settings.max_ptree_nodes = std::stoi(value);
            else if (name == "ptree_thresh_mult")
                recon_settings.ptree_thresh_mult = std::stoi(value);
            else if (name == "P_SKS_STRING")
                recon_settings.P_SKS_STRING = value;
            else if (name == "sks_zp_bytes")
                recon_settings.sks_zp_bytes = std::stoi(value);
            else if (name == "hashquery_len")
                recon_settings.hashquery_len = std::stoi(value);
            else if (name == "reconciliation_timeout")
                recon_settings.reconciliation_timeout = std::stoi(value);
            else if (name == "peaks_version")
                recon_settings.peaks_version = value;
            else if (name == "peaks_recon_port")
                recon_settings.peaks_recon_port = std::stoi(value);
            else if (name == "peaks_http_port")
                recon_settings.peaks_http_port = std::stoi(value);
            else if (name == "peaks_filters")
                recon_settings.peaks_filters = value;
            else if (name == "name")
                recon_settings.name = value;
            else if (name == "gossip_interval")
                recon_settings.gossip_interval = std::stoi(value);
            else if (name == "max_read_len_shift")
                recon_settings.max_read_len_shift = std::stoi(value);
            else if (name == "max_recover_size")
                recon_settings.max_recover_size = std::stoi(value);
            else if (name == "default_timeout")
                recon_settings.default_timeout = std::stoi(value);
            else if (name == "max_request_queue_len")
                recon_settings.max_request_queue_len = std::stoi(value);
            else if (name == "request_chunk_size")
                recon_settings.request_chunk_size = std::stoi(value);
            else if (name == "max_outstanding_recon_req")
                recon_settings.max_outstanding_recon_req = std::stoi(value);
            else if (name == "sks_compliant")
                recon_settings.sks_compliant = std::stoi(value);
            else if (name == "custom_hash_file_on")
                recon_settings.custom_hash_file_on = std::stoi(value);
            else if (name == "custom_hash_file")
                recon_settings.custom_hash_file = value;
            else if (name == "sks_bitstring")
                recon_settings.sks_bitstring = std::stoi(value);
        }
        recon_settings.num_samples = recon_settings.mbar + 1;
        recon_settings.split_threshold = recon_settings.ptree_thresh_mult * recon_settings.mbar;
        recon_settings.join_threshold = recon_settings.split_threshold / 2;
        recon_settings.max_read_len = 1 << recon_settings.max_read_len_shift;
        NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(recon_settings.P_SKS_STRING.c_str()));
        g_logger.log(Logger_level::DEBUG, "Config sks_compliant = " + std::to_string(recon_settings.sks_compliant));
    }
    else {
        std::cerr << "Couldn't open config file for reading.\n";
        exit(0);
    }
}

std::vector<NTL::ZZ_p> parse_custom_hash_file(){
    std::ifstream infile(recon_settings.custom_hash_file);
    NTL::ZZ_p hash;
    std::vector<NTL::ZZ_p> res;
    while (infile >> hash)
        res.push_back(hash);
    return res;
}

void build(){
    
    std::cout << "Starting ptree builder" << std::endl;
    const std::vector<NTL::ZZ_p> points = Utils::Zpoints(recon_settings.num_samples);
    std::shared_ptr<RECON_DBManager> dbm = std::make_shared<RECON_DBManager>();
    MemTree tree(dbm, points);
    g_logger.log(Logger_level::DEBUG, "created empty ptree");
    int entries;
    if (recon_settings.custom_hash_file_on == 1){
        std::vector<NTL::ZZ_p> hashes = parse_custom_hash_file();
        entries = hashes.size();
        for (auto hash : hashes){
            tree.insert(hash);
        }
    }
    else{
        std::vector<std::string> hashes;
        hashes = dbm->get_all_hash();
        entries = hashes.size();
        for (auto hash : hashes){
            tree.insert(hash);
        }
    }
    g_logger.log(Logger_level::DEBUG, "fetched hashes from DB");

    dbm->lockTables();
    tree.commit_memtree();
    dbm->unlockTables();
    g_logger.log(Logger_level::DEBUG, "populated ptree");
    std::cout << "Inserted " << entries << " entry!" << std::endl; 
    std::cout << "Finished! Now run without -b to start reconing!" << std::endl; 
    exit(0);
}

void run(){

    std::cout << "Starting recon_daemon" << std::endl;
    const std::vector<NTL::ZZ_p> points = Utils::Zpoints(recon_settings.num_samples);
    std::shared_ptr<RECON_DBManager> dbm = std::make_shared<RECON_DBManager>(); 
    Ptree tree(dbm, points);
    tree.create();
    Peer peer = Peer(tree);
    peer.start();
    exit(0);
}
