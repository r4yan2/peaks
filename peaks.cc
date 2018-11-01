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

#include <syslog.h>
#include <thread>
#include <cstring>
#include "DBManager.h"
#include "Thread_Pool.h"
#include "utils.h"
#include "unpacker.h"

#include <stdio.h>
#include <dirent.h>
/** declaring global recon_settings, which will hold the settings for peaks */
Configtype recon_settings;
namespace po = boost::program_options;

/** help function shows up the help message when command line is incorrect */
void help();

/** function to parse config file
 * @param filename string which hold the name of the config file
 * @param vm variables_map of boost::program_options, because command line by default overrides config file
 */
void parse_config(std::string filename, po::variables_map &vm);

/** helper to remove content of given directory
 * @param foldername folder to clean
 */
void remove_directory_content(const std::string &foldername);

/** peaks serve starter */
void serve(int argc, char* argv[]);

/** peaks import starter */
void import(po::variables_map &vm);

/** peaks build starter */
void build(po::variables_map &vm);

/** peaks recon starter */
void recon(po::variables_map vm);

void generate_csv(std::vector<std::string> files, boost::filesystem::path &path, unsigned int nThreads, unsigned int key_per_thread, int fastimport);
void import_csv(std::shared_ptr<DBManager> dbm, int fastimport);
/** \mainpage Peaks Keyserver Documentation
 *
 * \section intro_sec Introduction
 *
 * Peaks Keyserver is a new generation keyserver which aims
 * to be fully functional, compatible with other keyservers,
 * easy to deploy and mantain and with a low resource footprint.
 *
 * \section install_sec Installation
 *
 * \subsection step1 Step 1: Read the installation guide on Github
 *
 */

int main(int argc, char* argv[]){

    try{
	    po::options_description global("Global options");
	    global.add_options()
        ("help,h", "Print this help message")
        ("debug,d", "Turn on debug output")
        ("log-to-file,f", po::value<std::string>()->default_value(""), "Redirect log to the specified file")
        ("config, c", po::value<std::string>()->default_value("./peaks_config"), "Specify path of the config file (Default is in the same directory of peaks executable)")
        ("command", po::value<std::string>()->required(), "command to execute")
        ("subargs", po::value<std::vector<std::string> >(), "Arguments for command");

	    po::positional_options_description pos;
	    pos.add("command", 1).add("subargs", -1);

	    po::variables_map vm;

	    po::parsed_options parsed = po::command_line_parser(argc, argv).options(global).positional(pos).allow_unregistered().run();

	    po::store(parsed, vm);

        if (vm.count("help"))
            help();

        std::string cmd = vm["command"].as<std::string>();

        std::string filename = "peaks_config";
        parse_config(filename, vm);
        g_logger.init(vm.count("debug"), vm["log-to-file"].as<std::string>());
        
        if (cmd == "serve"){
            po::options_description serve_desc("serve options");
            std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
            if (std::find(opts.begin(), opts.end(), "-c") == opts.end()){
                opts.push_back("-c");
                opts.push_back(recon_settings.cppcms_config);
            }
            std::vector<char *> new_argv;
            std::transform(opts.begin(), opts.end(), std::back_inserter(new_argv), [](const std::string s) -> char* {
                    char *pc = new char[s.size() + 1];
                    std::strcpy(pc, s.c_str());
                    return pc;
                    }
                    );
            serve(opts.size(), &new_argv[0]);
	    }
        else if (cmd == "build"){
            po::options_description build_desc("build options");
            build(vm);
            }
        else if (cmd == "import"){
            po::options_description import_desc("import options");
            import_desc.add_options()
                ("threads, t", po::value<unsigned int>(), "set number of threads")
                ("keys, k", po::value<unsigned int>(), "set how many keys a thread has to analyze")
                ("path, p", po::value<boost::filesystem::path>(), "path to the dump")
                ("csv-only", "stop certificate import after creating csv")
                ("import-only", "start certificate import directly inserting csv into db")
                ("fastimport, f", "fastimport")
                ("noclean, n", "do not clean temporary folder");

            std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
            opts.erase(opts.begin());
            po::store(po::command_line_parser(opts).options(import_desc).run(), vm);
            import(vm);
            }
        else if (cmd == "recon"){
            po::options_description recon_desc("recon options");
            recon_desc.add_options()
                ("server-only", "start only sever part of recon")
                ("client-only", "start only client part of recon")
                ("dryrun", "dryrun");
            std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
            opts.erase(opts.begin());
            po::store(po::command_line_parser(opts).options(recon_desc).run(), vm);	
            recon(vm);
            }
        else{
                help();
            }
 
    po::notify(vm); // throws on error, so do after help in case 
                      // there are any problems 
    } 
    catch(boost::program_options::required_option& e) 
    { 
        std::cout << "Missing required option " << e.what() << std::endl;
        help();
    } 
    catch(boost::program_options::error& e) 
    { 
        std::cout << "Wrong option parameter " << e.what() << std::endl;
        help();
    } 
    catch(boost::exception& e){
        help();
    }
}

void help(){

    std::cout << "Usage: peaks [OPTIONS] COMMAND [ARGS]" << std::endl;

    std::cout << std::endl;

    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help \t\tPrint this help message" << std::endl;
    std::cout << "  -d, --debug \t\tTurn on debug output" << std::endl;
    std::cout << "  -f, --log-to-file \tRedirect log to the specified file" << std::endl;
    std::cout << "  -c, --config \t\tPath to the config file (If not provided it searches in the folder from which the executable is run)" << std::endl;

    std::cout << std::endl;

    std::cout << "Commands and args:" << std::endl;
    std::cout << "  import \t\tImport certificates into Mysql" << std::endl;
    std::cout << "    -t, --threads \tSet number of threads to use" << std::endl;
    std::cout << "    -k, --keys \t\tSet how many keys a thread has to analyze" << std::endl;
    std::cout << "    -p, --path \t\tSet the path of the dump" << std::endl;
    std::cout << "    --csv-only \tonly create temporary csv file, do not import into DB" << std::endl;
    std::cout << "    --import-only \tonly import temporary csv, do not create anything" << std::endl;
    std::cout << "    --noclean \tdo not clean temporary folder" << std::endl;
    std::cout << "    -f, --fastimport \tDo not unpack certificates" << std::endl;

    std::cout << std::endl; 

    std::cout << "  build \t\tBuild the prefix-tree" << std::endl;

    std::cout << std::endl;

    std::cout << "  recon \t\tStart the recon process" << std::endl;
    std::cout << "    --client-only \tStart only as client" << std::endl;
    std::cout << "    --server-only \tStart only as server" << std::endl;

    std::cout << std::endl;

    std::cout << "  serve \t\tStart the webserver process" << std::endl;
    std::cout << "    -c, --config \tspecify config file for cppcms" << std::endl;

    exit(0);
}

void parse_config(std::string filename, po::variables_map &vm){
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
            else if (name == "sks_bitstring")
                recon_settings.sks_bitstring = std::stoi(value);
            else if (name == "async_timeout_sec")
                recon_settings.async_timeout_sec = std::stoi(value);
            else if (name == "async_timeout_usec")
                recon_settings.async_timeout_usec = std::stoi(value);
            else if (name == "ignore_known_bug")
                recon_settings.ignore_known_bug = std::stoi(value) >= 1;

            else if (name == "db_host")
                recon_settings.db_host = value;
            else if (name == "db_database")
                recon_settings.db_database = value;
            else if (name == "db_user")
                recon_settings.db_user = value;
            else if (name == "db_password")
                recon_settings.db_password = value;

            else if (name == "membership_config")
                recon_settings.membership_config = value;
            else if (name == "cppcms_config")
                recon_settings.cppcms_config = value;

            else if (name == "default_dump_path")
                recon_settings.default_dump_path = value;
            else if (name == "tmp_folder_csv")
                recon_settings.tmp_folder_csv = value;
        }
        recon_settings.num_samples = recon_settings.mbar + 1;
        recon_settings.split_threshold = recon_settings.ptree_thresh_mult * recon_settings.mbar;
        recon_settings.join_threshold = recon_settings.split_threshold / 2;
        recon_settings.max_read_len = 1 << recon_settings.max_read_len_shift;
        NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(recon_settings.P_SKS_STRING.c_str()));
        recon_settings.points = Utils::Zpoints(recon_settings.num_samples);
        recon_settings.debug = vm.count("debug") >= 1;
        recon_settings.dry_run = vm.count("dryrun") >= 1;

    }
    else {
        std::cerr << "Couldn't open config file for reading.\n";
        exit(0);
    }
}

//PEAKS_PTREE_BUILDER
void build(po::variables_map &vm){
    
    std::cout << "Starting ptree builder" << std::endl;
    std::shared_ptr<RECON_DBManager> dbm = std::make_shared<RECON_DBManager>();
    g_logger.log(Logger_level::DEBUG, "created empty ptree");
    int entries;
    std::vector<std::string> hashes;
    hashes = dbm->get_all_hash();
    entries = hashes.size();
    if (entries == 0){
        std::cout << "DB is empty! Aborting..." << std::endl;
        exit(0);
    }
    MemTree tree(dbm);
    int progress = 0;
    for (auto hash : hashes){
        tree.insert(hash);
        progress += 1;
        if (progress%1000 == 0){
            printf ("\rProgress: %3d%%", (progress*100)/entries);
            fflush(stdout);
        }
    }
    g_logger.log(Logger_level::DEBUG, "fetched hashes from DB");

    std::cout << std::endl;
    std::cout << "Writing resulting ptree to DB!" << std::endl;
    dbm->lockTables();
    tree.commit_memtree();
    dbm->unlockTables();
    std::cout << "Inserted " << entries << " entry!" << std::endl; 
    exit(0);
}

//PEAKS_RECON_DAEMON
void recon(po::variables_map vm){

    std::cout << "Starting recon_daemon" << std::endl;
    const std::vector<NTL::ZZ_p> points = Utils::Zpoints(recon_settings.num_samples);
    std::shared_ptr<RECON_DBManager> dbm = std::make_shared<RECON_DBManager>(); 
    Ptree tree(dbm);
    if (tree.create()){
        std::cout << "pTree appears to be empty...Exiting for your server satefy.\nIf you know what you're doing restart peaks to continue, this is a one-time check" << std::endl;
        exit(0);
    }
    Peer peer = Peer(tree);
    if (vm.count("server-only"))
        peer.start_server();
    else if (vm.count("client-only"))
        peer.start_client();
    else
        peer.start();
    exit(0);
}

//PEAKS_CGI_HANDLER
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
void import(po::variables_map &vm) {

    std::cout << Utils::getCurrentTime() << "Starting unpacker" << std::endl;

    openlog("pgp_dump_import", LOG_PID, LOG_USER);
    setlogmask (LOG_UPTO (LOG_NOTICE));
    syslog(LOG_NOTICE, "Dump_import is starting up!");
    unsigned int nThreads = std::thread::hardware_concurrency() - 1;
    unsigned int key_per_thread;
    boost::filesystem::path path = recon_settings.default_dump_path;
    boost::filesystem::path csv_path = recon_settings.tmp_folder_csv;

    if(vm.count("path"))
        path = vm["path"].as<boost::filesystem::path>();
    else
        std::cout << "No custom path selected" << std::endl;
    
    std::cout << "Searching for certificates in: " << path << std::endl;

    std::vector<std::string> files;
    try {
        files = Utils::get_dump_files(path);
    }catch (std::exception &e){
        std::cerr << "Unable to read dump folder/files" << std::endl;
        exit(-1);
    }
    if (files.size() == 0){
        std::cout << "Found no key to import! Aborting..." << std::endl;
        exit(0);
    }else{
    std::cout << "Found " << files.size() << " keys to import" << std::endl;
    }

    if(vm.count("threads"))
        nThreads = vm["threads"].as<unsigned int>();
    
    std::cout << "Threads: " << nThreads << std::endl;

    if(vm.count("keys"))
        key_per_thread = vm["keys"].as<unsigned int>();
    else
        key_per_thread = 1 + ((files.size() - 1)/nThreads); 
    
    std::cout << "Key per Thread: " << key_per_thread << std::endl;


    if(Utils::create_folders() == -1){
        std::cerr << "Unable to create temp folder" << std::endl;
        exit(-1);
    }

    std::shared_ptr<DBManager> dbm = std::make_shared<DBManager>();

    if (!(vm.count("import-only")))
        generate_csv(files, path, nThreads, key_per_thread, vm.count("fastimport"));
    if (!(vm.count("csv-only")))
        import_csv(dbm, vm.count("fastimport"));
    if (vm.count("noclean") == 0){
        std::cout << Utils::getCurrentTime() << "Cleaning temporary folder." << std::endl;
        remove_directory_content(recon_settings.tmp_folder_csv);
    }else{
        std::cout << Utils::getCurrentTime() << "Not removing temporary csv fileiles as user request." << std::endl;
    }

    syslog(LOG_NOTICE, "Dump_import is stopping!");

}

void generate_csv(std::vector<std::string> files, boost::filesystem::path &path, unsigned int nThreads, unsigned int key_per_thread, int fastimport){
    std::cout << Utils::getCurrentTime() << "Starting dump read" << std::endl;

    std::shared_ptr<Thread_Pool> pool = std::make_shared<Thread_Pool>();
    std::vector<std::thread> pool_vect(nThreads);

    for (unsigned int i = 0; i < nThreads; i++){
        pool_vect[i] = std::thread([=] { pool->Infinite_loop_function(); });
    }

    for (unsigned int i = 0; i < files.size();){
        std::vector<std::string> dump_file_tmp;
        for (unsigned int j = 0; i < files.size() && j < key_per_thread; j++, i++){
            dump_file_tmp.push_back(files[i]);
        }
        pool->Add_Job([=] { return Unpacker::unpack_dump_th(dump_file_tmp, fastimport); });
    }

    pool->Stop_Filling_UP();

    for (auto &th: pool_vect){
        while (!th.joinable()){}
        th.join();
    }
}

void import_csv(std::shared_ptr<DBManager> dbm, int fastimport){

    std::cout << Utils::getCurrentTime() << "Writing dumped packet in DB:" << std::endl;

    dbm->lockTables();
    std::cout << Utils::getCurrentTime() << "\tInserting Certificates" << std::endl;
    dbm->insertCSV(Utils::get_files(Utils::CERTIFICATE), Utils::CERTIFICATE);
    if (fastimport == 0){
        std::cout << Utils::getCurrentTime() << "\tInserting Pubkeys" << std::endl;
        dbm->insertCSV(Utils::get_files(Utils::PUBKEY), Utils::PUBKEY);
        std::cout << Utils::getCurrentTime() << "\tInserting UserID" << std::endl;
        dbm->insertCSV(Utils::get_files(Utils::USERID), Utils::USERID);
        std::cout << Utils::getCurrentTime() << "\tInserting User Attributes" << std::endl;
        dbm->insertCSV(Utils::get_files(Utils::USER_ATTRIBUTES), Utils::USER_ATTRIBUTES);
        std::cout << Utils::getCurrentTime() << "\tInserting Signatures" << std::endl;
        dbm->insertCSV(Utils::get_files(Utils::SIGNATURE), Utils::SIGNATURE);
        std::cout << Utils::getCurrentTime() << "\tInserting SelfSignatures" << std::endl;
        dbm->insertCSV(Utils::get_files(Utils::SELF_SIGNATURE), Utils::SELF_SIGNATURE);
        std::cout << Utils::getCurrentTime() << "\tInserting Unpacker Errors" << std::endl;
        dbm->insertCSV(Utils::get_files(Utils::UNPACKER_ERRORS), Utils::UNPACKER_ERRORS);
        std::cout << Utils::getCurrentTime() << "\tInserting Broken Keys" << std::endl;
        dbm->insertCSV(Utils::get_files(Utils::BROKEN_KEY), Utils::BROKEN_KEY);

        std::cout << Utils::getCurrentTime() << "Updating DB fields:" << std::endl;

        std::cout << Utils::getCurrentTime() << "\tUpdating issuing fingerprint in Signatures" << std::endl;
        dbm->UpdateSignatureIssuingFingerprint();

        std::cout << Utils::getCurrentTime() << "\tUpdating issuing username in Signatures" << std::endl;
        dbm->UpdateSignatureIssuingUsername();

        std::cout << Utils::getCurrentTime() << "\tSetting expired flag" << std::endl;
        dbm->UpdateIsExpired();

        std::cout << Utils::getCurrentTime() << "\tSetting revoked flag" << std::endl;
        dbm->UpdateIsRevoked();

        std::cout << Utils::getCurrentTime() << "\tSetting valid flag" << std::endl;
        dbm->UpdateIsValid();
    }

    dbm->unlockTables();

}


void remove_directory_content(const std::string &foldername)
{
    // These are data types defined in the "dirent" header
    DIR *theFolder = opendir(foldername.c_str());
    struct dirent *next_file;
    char filepath[256];

    while ( (next_file = readdir(theFolder)) != NULL )
    {
        // build the path for each file in the folder
        sprintf(filepath, "%s/%s", foldername.c_str(), next_file->d_name);
        remove(filepath);
    }
    closedir(theFolder);
}
