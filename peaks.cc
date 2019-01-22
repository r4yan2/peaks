#include <fstream>
#include <string>
#include <iostream>
#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <exception>
#include <syslog.h>
#include <cstring>
#include <thread>

#include "cgi_handler/pks.h"
#include "recon_daemon/recon_daemon.h"
#include "unpacker/unpacker.h"
#include "dump_import/dump_import.h"
#include "analyzer/analyzer.h"

/** convenient renaming for program_options, totally optional */
namespace po = boost::program_options;

/** help function shows up the help message when command line is incorrect */
void help();

/** function to parse config file
 * @param filename string which hold the name of the config file
 * @param vm variables_map of boost::program_options, because command line by default overrides config file
 */
void parse_config(std::string filename, po::variables_map &vm);

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
        ("stdout", "Turn on debug on stdout")
        ("config, c", po::value<std::string>(), "Specify path of the config file (Default is in the same directory of peaks executable)")
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

        std::vector<std::string> filenames;
        if (vm.count("config"))
            filenames.insert(filenames.begin(), vm["config"].as<std::string>());
        filenames.push_back("peaks_config");
        filenames.push_back("/var/lib/peaks/peaks_config");
        filenames.push_back("/etc/peaks/peaks_config");

        bool parsed_config = false;
        for (auto filename: filenames){
            try{
                parse_config(filename, vm);
                parsed_config = true;
                break;
            }
            catch(std::runtime_error& e){
                continue;
            }
        }

        if (!(parsed_config))
            exit(0);
        
        if (cmd == "serve"){
            serve(vm, parsed);
	    }
        else if (cmd == "build"){
            //po::options_description build_desc("build options");
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
                ("selection, s", po::value<int>()->default_value(-1), "select which table to import")
                ("noclean, n", "do not clean temporary folder");

            std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
            opts.erase(opts.begin());
            po::store(po::command_line_parser(opts).options(import_desc).run(), vm);
            Importer importer = Importer();
            importer.import(vm);
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
        		std::this_thread::sleep_for(std::chrono::seconds{vm["gossip_interval"].as<int>()});
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
        		std::this_thread::sleep_for(std::chrono::seconds{vm["gossip_interval"].as<int>()});
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
            recon(vm);
            }
        else{
                std::cout << "Unrecognized command " << cmd << std::endl;
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
        std::cout << "Caught exception" << boost::diagnostic_information(e) << std::endl;
    }
}

void help(){

    std::cout << "Usage: peaks [OPTIONS] COMMAND [ARGS]" << std::endl;

    std::cout << std::endl;

    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help \t\tPrint this help message" << std::endl;
    std::cout << "  -d, --debug \t\tTurn on debug output" << std::endl;
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
    std::cout << "searching config file " << filename << std::endl;
    std::ifstream cFile (filename);
    if (cFile.is_open())
    {
        std::cout << "config file found!" << std::endl;
        po::options_description config("Configuration");
        config.add_options()
            ("mbar", po::value<int>())
            ("bq", po::value<int>())
            ("max_ptree_nodes", po::value<int>())
            ("ptree_thresh_mult", po::value<int>())
            ("P_SKS_STRING", po::value<std::string>())
            ("reconciliation_timeout", po::value<int>())
            ("peaks_version", po::value<std::string>())
            ("peaks_recon_port", po::value<int>())
            ("peaks_http_port", po::value<int>())
            ("peaks_filters", po::value<std::string>())
            ("name", po::value<std::string>())
            ("gossip_interval", po::value<int>())
            ("max_read_len_shift", po::value<int>())
            ("max_recover_size", po::value<int>())
            ("default_timeout", po::value<int>())
            ("max_request_queue_len", po::value<int>())
            ("request_chunk_size", po::value<int>())
            ("max_outstanding_recon_req", po::value<int>())
            ("sks_bitstring", po::value<int>())
            ("async_timeout_sec", po::value<int>())
            ("async_timeout_usec", po::value<int>())
            ("ignore_known_bug", po::value<int>())
            ("unpack_on_import", po::value<int>())
            ("max_unpacker_limit", po::value<unsigned int>())

            ("db_user", po::value<std::string>())
            ("db_host", po::value<std::string>())
            ("db_database", po::value<std::string>())
            ("db_password", po::value<std::string>()->default_value(""))
            ("membership_config", po::value<std::string>())
            ("cppcms_config", po::value<std::string>())
            ("default_dump_path", po::value<std::string>())
            ("analyzer_tmp_folder", po::value<std::string>())
            ("analyzer_error_folder", po::value<std::string>())
            ("analyzer_gcd_folder", po::value<std::string>())
            ("unpacker_tmp_folder", po::value<std::string>())
            ("unpacker_error_folder", po::value<std::string>())
            ("recon_tmp_folder", po::value<std::string>())
            ("dumpimport_tmp_folder", po::value<std::string>())
            ("dumpimport_error_folder", po::value<std::string>())
            ;
        po::store(po::parse_config_file(cFile, config, false), vm);
        vm.insert(std::make_pair("sks_zp_bytes", po::variable_value(17, false)));
        vm.insert(std::make_pair("hashquery_len", po::variable_value(16, false)));
        vm.insert(std::make_pair("num_samples", po::variable_value(vm["mbar"].as<int>() + 1, false)));
        vm.insert(std::make_pair("split_threshold", po::variable_value(vm["ptree_thresh_mult"].as<int>() * vm["mbar"].as<int>(), false)));
        vm.insert(std::make_pair("join_threshold", po::variable_value(vm["split_threshold"].as<int>() / 2, false)));
        vm.insert(std::make_pair("max_read_len", po::variable_value(1 << vm["max_read_len_shift"].as<int>(), false)));

    }
    else {
        throw std::runtime_error("Couldn't open config file for reading");
    }
}


