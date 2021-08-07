#include <boost/exception/diagnostic_information.hpp>
#include <exception>
#include <syslog.h>
#include <cstring>
#include <thread>
#include <csignal>
#include <boost/stacktrace.hpp>

#include "peaks.h"
#include <common/config.h>
#include <cgi_handler/pks.h>
#include <recon_daemon/recon_daemon.h>
#include <unpacker/unpacker.h>
#include <import/import.h>
#include <analyzer/analyzer.h>
#include <dump/dump.h>

using namespace peaks::dump;
using namespace peaks::import;
using namespace peaks::recon;
using namespace peaks::pks;
using namespace peaks::analyzer;
using namespace peaks::unpacker;

using namespace peaks;

/** \mainpage Peaks Keyserver Documentation
 *
 * \section intro_sec Introduction
 *
 * Peaks Keyserver is a new generation keyserver which aims
 * to be fully functional, compatible with other keyservers,
 * easy to deploy and mantain and with a low resource footprint.
 *
 */
 
/** signal handler when SIGINT or SIGTERM are catched
 */
bool sleeping = false;
void signalHandler(int signum) {
    switch(signum){
        case SIGINT:
        case SIGTERM:
            if (sleeping)
                exit(0);
            else{
                std::cerr << "Shutting Down..." << std::endl;
                Context::context().quitting = true;
            }
            break;
        case SIGSEGV:
            std::cerr << boost::stacktrace::stacktrace() << std::endl;
            exit(1);
        default:
            syslog(LOG_WARNING, "Error: unkown signal caught: %d", signum);
    }
}

int main(int argc, char* argv[]){
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    std::signal(SIGSEGV, signalHandler);
    Context::context().quitting = false;

    try{
	    po::options_description global("Global options");
	    global.add_options()
        ("help,h", "Print this help message")
        ("debug,d", "Turn on debug output")
        ("stdout,s", "Turn on debug on stdout")
        ("config,c", po::value<std::string>(), "Specify path of the config file (Default is in the same directory of peaks executable)")
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
                std::cout << "searching config file " << filename << std::endl;
                std::ifstream cFile(filename);
                if (cFile.is_open()){
                    parse_config(cFile, vm);
                    parsed_config = true;
                    break;
                }
        }

        if (parsed_config)
            std::cout << "config file found!" << std::endl;
        else
            exit(0);

        if (cmd == "serve"){
            Context::context().vm = vm;
            serve(vm);
	    }
        else if (cmd == "build"){
            //po::options_description build_desc("build options");
            build(vm);
            }
        else if (cmd == "dump"){
            po::options_description dump_desc("dump options");
            dump_desc.add_options()
                ("threads, t", po::value<unsigned int>(), "set number of threads")
                ("outdir, o", po::value<std::string>(), "set output dir");
            std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
            opts.erase(opts.begin());
            po::store(po::command_line_parser(opts).options(dump_desc).run(), vm);
            Dump::dump(vm);
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
            Importer importer;
            Context::context().vm = vm;
            importer.import();
            }
        else if (cmd == "unpack"){
            po::options_description unpack_desc("unpack options");
            unpack_desc.add_options()
                ("threads, t", po::value<unsigned int>(), "set number of threads")
                ("keys, k", po::value<unsigned int>(), "set how many keys a thread has to analyze")
                ("limit, l", po::value<unsigned int>(), "set limit to how many keys to unpack per run")
                ("recover, r", "recover");

            std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
            opts.erase(opts.begin());
            po::store(po::command_line_parser(opts).options(unpack_desc).run(), vm);
            Unpacker unpacker(vm);
            while(true){
                if (Context::context().quitting)
                    exit(0);
            	unpacker.run();
                sleeping = true;
        		std::this_thread::sleep_for(std::chrono::seconds{vm["gossip_interval"].as<int>()});
                sleeping = false;
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
            Analyzer analyzer(vm);
            
            while(true){
                if (Context::context().quitting)
                    exit(0);
            	analyzer.run();
                sleeping = true;
        		std::this_thread::sleep_for(std::chrono::seconds{vm["gossip_interval"].as<int>()});
                sleeping = false;
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
            Recon recon(vm);
            recon.run();
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
    catch(std::exception &e){
        std::cout << e.what() << std::endl;
        help();
    }
}

