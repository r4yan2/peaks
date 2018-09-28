#include "cgi_handler/pks.h"
#include "recon_daemon/logger.h"
#include "recon_daemon/Recon_settings.h"
#include "recon_daemon/Utils.h"
#include "recon_daemon/RECON_DBManager.h"
#include "recon_daemon/peer.h"
#include "recon_daemon/pTreeDB.h"
#include <fstream>
#include <string>
#include <NTL/ZZ_p.h>
#include <iostream>
#include <boost/program_options.hpp>
#include <chrono>

Configtype recon_settings;
namespace po = boost::program_options;

void help();
void parse_config(std::string filename);
void serve(int argc, char* argv[]);
void import(int argc, char* argv[]);
void build();
void recon(int mode);
char* convert(const std::string & s);
std::vector<NTL::ZZ_p> parse_custom_hash_file();

int main(int argc, char* argv[]){

    try{
	    po::options_description global("Global options");
	    global.add_options()
        ("debug,d", "Turn on debug output")
        ("command", po::value<std::string>()->required(), "command to execute")
        ("subargs", po::value<std::vector<std::string> >(), "Arguments for command");

	    po::positional_options_description pos;
	    pos.add("command", 1).add("subargs", -1);

	    po::variables_map vm;

	    po::parsed_options parsed = po::command_line_parser(argc, argv).options(global).positional(pos).allow_unregistered().run();

	    po::store(parsed, vm);

	    std::string cmd = vm["command"].as<std::string>();

        std::string filename = "recon_config";
        parse_config(filename);
        g_logger.init(vm.count("debug"));

	    if (cmd == "serve"){
            po::options_description serve_desc("serve options");
            std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
            //should erase first, but insted pass from 1
            //opts.erase(opts.begin());
            std::vector<char *> new_argv;
            std::transform(opts.begin(), opts.end(), std::back_inserter(new_argv), convert);
            serve(opts.size(), &new_argv[0]);
	    }
	    else if (cmd == "build"){
            po::options_description build_desc("build options");
            build();
        }
        else if (cmd == "import"){
            po::options_description import_desc("import options");
            import_desc.add_options()
                ("t", po::value<int>(), "set number of threads")
                ("k", po::value<int>(), "set how many keys a thread has to analyze")
	            ("p", po::value<std::string>(), "path to the dump");

            std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
            //opts.erase(opts.begin());
            std::vector<char *> new_argv;
            std::transform(opts.begin(), opts.end(), std::back_inserter(new_argv), convert);
            import(opts.size(), &new_argv[0]);

            //po::store(po::command_line_parser(opts).options(import_desc).run(), vm);	
	    }
        else if (cmd == "recon"){
            po::options_description recon_desc("recon options");
            recon_desc.add_options()
                ("server-only", "start only sever part of recon")
                ("client-only", "start only client part of recon");
            std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
            opts.erase(opts.begin());
            po::store(po::command_line_parser(opts).options(recon_desc).run(), vm);	
            if (vm.count("server-only") == 1)
                recon(1);
            else if (vm.count("client-only") == 1)
                recon(2);
            else recon(0);
        }
        else {
            help();
        }
 
    po::notify(vm); // throws on error, so do after help in case 
                      // there are any problems 
    } 
    catch(boost::program_options::required_option& e) 
    { 
        std::cout << "Missing required option:" << std::endl;
    } 
    catch(boost::program_options::error& e) 
    { 
        std::cout << "Wrong option parameter:" << std::endl;
    } 
    catch(boost::exception& e){
        help();
    }
}

void help(){

    std::cout << "Usage:" << std::endl;
    std::cout << "recon_daemon [-d|--debug] command [command-options]" << std::endl;
    std::cout << std::endl;
    std::cout << "-d enable more verbose log" << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "import - Import certificated into Mysql" << std::endl;
    std::cout << "build - build the prefix-tree" << std::endl;
    std::cout << "recon - start the recon process" << std::endl;
    std::cout << "serve - start the server process" << std::endl;
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
            else if (name == "async_timeout_sec")
                recon_settings.async_timeout_sec = std::stoi(value);
            else if (name == "async_timeout_usec")
                recon_settings.async_timeout_usec = std::stoi(value);
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
    std::cout << "Finished! Now recon without -b to start reconing!" << std::endl; 
    exit(0);
}

void recon(int mode){

    std::cout << "Starting recon_daemon" << std::endl;
    const std::vector<NTL::ZZ_p> points = Utils::Zpoints(recon_settings.num_samples);
    std::shared_ptr<RECON_DBManager> dbm = std::make_shared<RECON_DBManager>(); 
    Ptree tree(dbm, points);
    tree.create();
    Peer peer = Peer(tree);
    if (mode == 0)
        peer.start();
    else if (mode == 1)
        peer.start_server();
    else if (mode == 2)
        peer.start_client();
    exit(0);
}

//PEAKS_CGI_HANDLER
//
void serve(int argc, char* argv[]){
    openlog("peaks", LOG_PID, LOG_USER);
    setlogmask (LOG_UPTO (LOG_NOTICE));
    syslog(LOG_NOTICE, "peaks server is starting up!");
    try {
        cppcms::service srv(argc, argv);
        srv.applications_pool().mount(cppcms::applications_factory<peaks::Pks>());
        srv.run();
    }
    catch(std::exception const &e) {
        std::cerr << e.what() << std::endl;
        syslog(LOG_CRIT, "Error during starting up: %s", e.what());
    }

    std::cout << "Exiting..." << std::endl;
    closelog();
}

// PEAKS_DB_MAIN
//
#include <iostream>
#include <syslog.h>
#include <thread>
#include <cstring>
#include "DBManager.h"
#include "Thread_Pool.h"
#include "utils.h"
#include "unpacker.h"

using namespace Utils;
using namespace std;
using namespace std::chrono_literals;

void printHelp();

void import(int argc, char* argv[]) {

    cout << Utils::getCurrentTime() << "Starting unpacker" << endl;

    openlog("pgp_dump_import", LOG_PID, LOG_USER);
    setlogmask (LOG_UPTO (LOG_NOTICE));
    syslog(LOG_NOTICE, "Dump_import is starting up!");
    unsigned int nThreads = thread::hardware_concurrency() / 2;
    unsigned int key_per_thread = KEY_PER_THREAD_DEFAULT;
    boost::filesystem::path path = DEFAULT_DUMP_PATH;
    const char *MINUS_T = "-t";
    const char *MINUS_P = "-p";
    const char *MINUS_H = "-h";
    const char *MINUS_K = "-k";

    for (int i = 1; i < argc; i++){
        if(!strcmp(argv[i], MINUS_H)){
            printHelp();
            exit(0);
        }
        else if(!strcmp(argv[i], MINUS_P)){
            try{
                path = argv[++i];
            }catch (...){
                path = DEFAULT_DUMP_PATH;
            }
        }
        else if(!strcmp(argv[i], MINUS_T)){
            try{
                nThreads = static_cast<unsigned int>(stoul(argv[++i]));
            }catch (...){
                nThreads = thread::hardware_concurrency() / 2;
            }
        }
        else if(!strcmp(argv[i], MINUS_K)){
            try{
                key_per_thread = static_cast<unsigned int>(stoul(argv[++i]));
            }catch (...){
                key_per_thread = KEY_PER_THREAD_DEFAULT;
            }
        }
        else{
            cout << "Option not recognized: " << argv[i] << endl;
            exit(0);
        }
    }

    if(Utils::create_folders() == -1){
        cerr << "Unable to create temp folder" << endl;
        exit(-1);
    }

    cout << "Threads: " << nThreads << endl;
    cout << "Key per Thread: " << key_per_thread << endl;

    shared_ptr<DBManager> dbm = make_shared<DBManager>();

    cout << Utils::getCurrentTime() << "Starting dump read" << endl;

    vector<string> files;
    try {
        files = Utils::get_dump_files(path);
    }catch (exception &e){
        cerr << "Unable to read dump folder/files" << endl;
        exit(-1);
    }

    shared_ptr<Thread_Pool> pool = make_shared<Thread_Pool>();
    vector<thread> pool_vect(nThreads);

    for (unsigned int i = 0; i < nThreads; i++){
        pool_vect[i] = thread([=] { pool->Infinite_loop_function(); });
    }

    for (unsigned int i = 0; i < files.size();){
        vector<string> dump_file_tmp;
        for (unsigned int j = 0; i < files.size() && j < key_per_thread; j++, i++){
            dump_file_tmp.push_back(files[i]);
        }
        pool->Add_Job([=] { return Unpacker::unpack_dump_th(dump_file_tmp); });
    }

    pool->Stop_Filling_UP();

    for (auto &th: pool_vect){
        while (!th.joinable()){}
        th.join();
    }

    cout << Utils::getCurrentTime() << "Writing dumped packet in DB:" << endl;

    dbm->lockTables();
    cout << Utils::getCurrentTime() << "\tInserting Certificates" << endl;
    dbm->insertCSV(Utils::get_files(Utils::CERTIFICATE), Utils::CERTIFICATE);
    cout << Utils::getCurrentTime() << "\tInserting Pubkeys" << endl;
    dbm->insertCSV(Utils::get_files(Utils::PUBKEY), Utils::PUBKEY);
    cout << Utils::getCurrentTime() << "\tInserting UserID" << endl;
    dbm->insertCSV(Utils::get_files(Utils::USERID), Utils::USERID);
    cout << Utils::getCurrentTime() << "\tInserting User Attributes" << endl;
    dbm->insertCSV(Utils::get_files(Utils::USER_ATTRIBUTES), Utils::USER_ATTRIBUTES);
    cout << Utils::getCurrentTime() << "\tInserting Signatures" << endl;
    dbm->insertCSV(Utils::get_files(Utils::SIGNATURE), Utils::SIGNATURE);
    cout << Utils::getCurrentTime() << "\tInserting SelfSignatures" << endl;
    dbm->insertCSV(Utils::get_files(Utils::SELF_SIGNATURE), Utils::SELF_SIGNATURE);
    cout << Utils::getCurrentTime() << "\tInserting Unpacker Errors" << endl;
    dbm->insertCSV(Utils::get_files(Utils::UNPACKER_ERRORS), Utils::UNPACKER_ERRORS);
    cout << Utils::getCurrentTime() << "\tInserting Broken Keys" << endl;
    dbm->insertCSV(Utils::get_files(Utils::BROKEN_KEY), Utils::BROKEN_KEY);

    cout << Utils::getCurrentTime() << "Updating DB fields:" << endl;

    cout << Utils::getCurrentTime() << "\tUpdating issuing fingerprint in Signatures" << endl;
    dbm->UpdateSignatureIssuingFingerprint();

    cout << Utils::getCurrentTime() << "\tUpdating issuing username in Signatures" << endl;
    dbm->UpdateSignatureIssuingUsername();

    cout << Utils::getCurrentTime() << "\tSetting expired flag" << endl;
    dbm->UpdateIsExpired();

    cout << Utils::getCurrentTime() << "\tSetting revoked flag" << endl;
    dbm->UpdateIsRevoked();

    cout << Utils::getCurrentTime() << "\tSetting valid flag" << endl;
    dbm->UpdateIsValid();

    dbm->unlockTables();

    syslog(LOG_NOTICE, "Dump_import is stopping!");

    cout << Utils::getCurrentTime() << "Dump_import terminated. Remember to create the ptree with the SKS executable "
            "before starting the recon." << endl;

}

void printHelp() {
    cout << "Peaks import help:" << endl;
    cout << "Parameters:" << endl;
    cout << "-t: set number of threads" << endl;
    cout << "-k: set how many keys a thread has to analyze" << endl;
    cout << "-p: set the path of the dump" << endl;
    cout << "The default value for this computer are:" << endl;
    cout << "t = " << thread::hardware_concurrency() / 2 << endl;
    cout << "k = " << KEY_PER_THREAD_DEFAULT << endl;
    cout << "p = " << DEFAULT_DUMP_PATH << endl;
}

char* convert(const std::string & s){
    char *pc = new char[s.size()+1];
    std::strcpy(pc, s.c_str());
    return pc; 
}
