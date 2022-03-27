#include <boost/exception/diagnostic_information.hpp>
#include <exception>
#include <syslog.h>
#include <cstring>
#include <thread>
#include <common/config.h>
#include <cgi_handler/pks.h>
#include <recon_daemon/recon_daemon.h>
#include <unpacker/unpacker.h>
#include <import/import.h>
#include <analyzer/analyzer.h>
#include <dump/dump.h>
#include <sys/syslog.h>
#include <csignal>
#include <execinfo.h>
#include <functional>

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

using namespace peaks;
void signalHandler(int signum) {
    fprintf(stderr, "Error: signal %d:\n", signum);
    switch(signum){
        case SIGINT:
        case SIGTERM:
            std::cerr << "Shutting Down..." << std::endl;
            while(CONTEXT.critical_section) {}
            exit(0);
        case SIGSEGV:
            void *array[10];
            size_t size;
            size = backtrace(array, 10);
            backtrace_symbols_fd(array, size, STDERR_FILENO);
            exit(1);
        default:
            syslog(LOG_WARNING, "Error: unkown signal caught: %d", signum);
    }
}

   void help(){
   
       std::cout << std::endl;
       std::cout << "Usage: peaks [OPTIONS] COMMAND [ARGS]" << std::endl;
       std::cout << std::endl;
   
       std::cout << "Options:" << std::endl;
       std::cout << "  -h, --help           Print this help message" << std::endl;
       std::cout << "  -d, --debug          Turn on debug output" << std::endl;
       std::cout << "  -c, --config         Path to the config file (If not provided it searches in the folder from which the executable is run)" << std::endl;
       std::cout << "  -s, --stdout         Turn on debug on console" << std::endl;
   
       std::cout << "Commands and args:" << std::endl;
       std::cout << std::endl;
   
       std::cout << "  serve                Start the webserver process" << std::endl;
       std::cout << std::endl;
   
       std::cout << "  build                Build the prefix-tree" << std::endl;
   
       std::cout << std::endl;
   
       std::cout << "  import               Import certificates into Mysql" << std::endl;
       std::cout << "    --init             Before loading keys initalize DB using specified file" << std::endl;
       std::cout << "    --threads          Set number of threads to use" << std::endl;
       std::cout << "    --path             Set the path of the dump" << std::endl;
       std::cout << "    --csv-only         only create temporary csv file, do not import into DB" << std::endl;
       std::cout << "    --import-only      only import temporary csv, do not create anything" << std::endl;
       std::cout << "    --noclean          do not clean temporary folder" << std::endl;
   
       std::cout << std::endl;
   
       std::cout << "  dump                 Dump database into csv files, currently output in MySQL directory" << std::endl;
       std::cout << "    --threads          Set number of threads to use" << std::endl;
       std::cout << "    --outdir           Set the output directory" << std::endl;
   
       std::cout << std::endl;
   
       std::cout << "  unpack               Unpack certificate not analyzer during fastimport" << std::endl;
       std::cout << "    --threads          Set number of threads to use" << std::endl;
       std::cout << "    --csv-only         only create temporary csv file, do not import into DB" << std::endl;
       std::cout << "    --limit            Set the limit on key to unpack" << std::endl;
       std::cout << "    --recover          Recover previous broken session only" << std::endl;
       std::cout << "    --reset            Reset DB unpacking status" << std::endl;
   
       std::cout << std::endl;
   
       std::cout << "  analyze              Perform security analysis on imported pubkeys" << std::endl;
       std::cout << "    --threads          Set number of threads to use" << std::endl;
       std::cout << "    --limit            Set the limit on key to analyze" << std::endl;
   
       std::cout << std::endl;
   
       std::cout << "  recon                Start the recon process" << std::endl;
       std::cout << "    --client-only      Start only as client" << std::endl;
       std::cout << "    --server-only      Start only as server" << std::endl;
       std::cout << "    --dryrun           Recon without inserting into DB" << std::endl;
   
       std::cout << std::endl;
       exit(0);
   }

    void write_config(){
        CONTEXT.write_config();
        exit(0);
    }

   int main(int argc, char* argv[]){
        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);
        std::signal(SIGSEGV, signalHandler);
        std::map<std::string, std::function<void()>> command_map = {
            std::make_pair("help", help),
            std::make_pair("config", write_config),
            std::make_pair("import", import::import),
            std::make_pair("unpack", unpacker::unpack),
            std::make_pair("recon", recon::recon),
            std::make_pair("build", recon::build),
            std::make_pair("serve", pks::serve),
            std::make_pair("dump", dump::dump),
            std::make_pair("analyze", analyzer::analyze)
        };
        try{
            std::string err = "";
            std::string cmd = CONTEXT.init_options(argc, argv);
            auto it = command_map.find(cmd);
            if (it == command_map.end()){
                std::cerr << "command " << cmd << " not recognized" << std::endl; 
                help();
                exit(0);
            }
            it->second();
        } 
        catch(boost::program_options::required_option& e) 
        { 
            std::cerr << "Missing required option " << e.what() << std::endl;
            help();
        } 
        catch(boost::program_options::error& e) 
        { 
            std::cerr << "Wrong option parameter " << e.what() << std::endl;
            help();
        } 
        catch(std::exception &e){
            std::cerr << e.what() << std::endl;
            help();
        }
   }
