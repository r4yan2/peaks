#include "cgi_handler/pks.h"
#include "recon_daemon/logger.h"
#include "recon_daemon/Recon_settings.h"
#include "recon_daemon/Utils.h"
#include "recon_daemon/DBManager.h"
#include "recon_daemon/peer.h"
#include "recon_daemon/pTreeDB.h"
#include <fstream>
#include <string>
#include <NTL/ZZ_p.h>
#include <iostream>
#include <boost/program_options.hpp>

#include <syslog.h>
#include <cstring>

#include "unpacker/unpacker.h"
#include "dump_import/dump_import.h"
#include "analyzer/analyzer.h"
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

/** peaks serve starter */
void serve(int argc, char* argv[]);

/** peaks build starter */
void build(po::variables_map &vm);

/** peaks recon starter */
void recon(po::variables_map vm);

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
        else if (cmd == "unpack"){
            po::options_description unpack_desc("unpack options");
            unpack_desc.add_options()
                ("threads, t", po::value<unsigned int>(), "set number of threads")
                ("keys, k", po::value<unsigned int>(), "set how many keys a thread has to analyze")
                ("limit, l", po::value<unsigned int>(), "set limit to how many keys to unpack per run");

            std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
            opts.erase(opts.begin());
            po::store(po::command_line_parser(opts).options(unpack_desc).run(), vm);
			while(true){
            	Unpacker::unpacker(vm);
        		std::this_thread::sleep_for(std::chrono::seconds{recon_settings.gossip_interval});
			}
        }
        else if (cmd == "analyze"){
            po::options_description analyzer_desc("analyzer options");
            analyzer_desc.add_options()
                ("threads, t", po::value<unsigned int>(), "set number of threads")
                ("keys, k", po::value<unsigned int>(), "set how many keys a thread has to analyze")
                ("limit, l", po::value<unsigned int>(), "set limit to how many keys to unpack per run");
            std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
            opts.erase(opts.begin());
            po::store(po::command_line_parser(opts).options(analyzer_desc).run(), vm);
			while(true){
            	analyzer(vm);
        		std::this_thread::sleep_for(std::chrono::seconds{recon_settings.gossip_interval});
			}

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
            recon_settings.dry_run = vm.count("dryrun") >= 1;
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

    std::cout << "Commands and args:" << std::endl;
    std::cout << std::endl;

    std::cout << "  serve \t\tStart the webserver process" << std::endl;
    std::cout << "    -c, --config \tspecify config file for cppcms" << std::endl;
    std::cout << std::endl;

    std::cout << "  build \t\tBuild the prefix-tree" << std::endl;

    std::cout << std::endl;

    std::cout << "  import \t\tImport certificates into Mysql" << std::endl;
    std::cout << "    -t, --threads \tSet number of threads to use" << std::endl;
    std::cout << "    -k, --keys \t\tSet how many keys a thread has to analyze" << std::endl;
    std::cout << "    -p, --path \t\tSet the path of the dump" << std::endl;
    std::cout << "    --csv-only \t\tonly create temporary csv file, do not import into DB" << std::endl;
    std::cout << "    --import-only \tonly import temporary csv, do not create anything" << std::endl;
    std::cout << "    -f, --fastimport \tDo not unpack certificates" << std::endl;
    std::cout << "    --noclean \t\tdo not clean temporary folder" << std::endl;

    std::cout << std::endl; 

    std::cout << "  unpack \t\tUnpack certificate not analyzer during fastimport" << std::endl;
    std::cout << "    -t, --threads \tSet number of threads to use" << std::endl;
    std::cout << "    -k, --keys \t\tSet how many keys a thread has to analyze" << std::endl;
    std::cout << "    -l, --limit \tSet the limit on key to unpack" << std::endl;

    std::cout << std::endl;

    std::cout << "  analyze \t\tPerform security analysis on imported pubkeys" << std::endl;
    std::cout << "    -t, --threads \tSet number of threads to use" << std::endl;
    std::cout << "    -k, --keys \t\tSet how many keys a thread has to analyze" << std::endl;
    std::cout << "    -l, --limit \tSet the limit on key to analyze" << std::endl;

    std::cout << std::endl;

    std::cout << "  recon \t\tStart the recon process" << std::endl;
    std::cout << "    --client-only \tStart only as client" << std::endl;
    std::cout << "    --server-only \tStart only as server" << std::endl;
    std::cout << "    --dryrun \t\tRecon without inserting into DB" << std::endl;

    std::cout << std::endl;
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

            else if (name == "max_unpacker_limit")
                recon_settings.max_unpacker_limit = std::stoi(value);
            else if (name == "analyzer_tmp_folder")
                recon_settings.analyzer_tmp_folder = value;
            else if (name == "analyzer_error_folder")
                recon_settings.analyzer_error_folder = value;
            else if (name == "unpacker_tmp_folder")
                recon_settings.unpacker_tmp_folder = value;
            else if (name == "recon_tmp_folder")
                recon_settings.recon_tmp_folder = value;
            else if (name == "unpacker_error_folder")
                recon_settings.unpacker_error_folder = value;
            else if (name == "dump_error_folder")
                recon_settings.dump_error_folder = value;
            else if (name == "tmp_folder_gcd")
                recon_settings.tmp_folder_gcd = value;
        }
        recon_settings.num_samples = recon_settings.mbar + 1;
        recon_settings.split_threshold = recon_settings.ptree_thresh_mult * recon_settings.mbar;
        recon_settings.join_threshold = recon_settings.split_threshold / 2;
        recon_settings.max_read_len = 1 << recon_settings.max_read_len_shift;
        NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(recon_settings.P_SKS_STRING.c_str()));
        recon_settings.points = RECON_Utils::Zpoints(recon_settings.num_samples);
        recon_settings.debug = vm.count("debug") >= 1;

    }
    else {
        std::cerr << "Couldn't open config file for reading.\n";
        exit(0);
    }
}

//PEAKS_PTREE_BUILDER
void build(po::variables_map &vm){
    
    std::cout << "Starting ptree builder" << std::endl;
    if (RECON_Utils::create_folders() != 0){
        std::cout << "Unable to create temporary directories!Exiting..." << std::endl;
        exit(1);
    }
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
    remove_directory_content(recon_settings.recon_tmp_folder);
    std::cout << "Inserted " << entries << " entry!" << std::endl; 
    exit(0);
}

//PEAKS_RECON_DAEMON
void recon(po::variables_map vm){

    std::cout << "Starting recon_daemon" << std::endl;
    const std::vector<NTL::ZZ_p> points = RECON_Utils::Zpoints(recon_settings.num_samples);
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


