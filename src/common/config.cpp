#include "config.h"
#include <boost/program_options/variables_map.hpp>
#include <common/utils.h>
#include <syslog.h>

using namespace peaks;
using namespace peaks::common;

Context::Context(){
    global.add_options()
        ("help,h", "Print this help message")
        ("debug,d", po::value<int>(), "Turn on debug output")
        ("stdout,s", "Turn on debug on stdout")
        ("config,c", po::value<std::string>(), "Specify path of the config file (Default is in the same directory of peaks executable)")
        ("command", po::value<std::string>()->required(), "command to execute")
        ("subargs", po::value<std::vector<std::string> >(), "Arguments for command")
    ;
    
    internal_config.add_options()
        ("mbar", po::value<int>()->default_value(5))
        ("bq", po::value<int>()->default_value(2))
        ("max_ptree_nodes", po::value<int>()->default_value(1000))
        ("ptree_thresh_mult", po::value<int>()->default_value(10))
        ("P_SKS_STRING", po::value<std::string>()->default_value("530512889551602322505127520352579437339"))
        ("reconciliation_timeout", po::value<int>()->default_value(45))
        ("default_timeout", po::value<int>()->default_value(300))
        ("max_read_len_shift", po::value<int>()->default_value(24))
        ("max_recover_size", po::value<int>()->default_value(1500))
        ("max_request_queue_len", po::value<int>()->default_value(60000))
        ("request_chunk_size", po::value<int>()->default_value(100))
        ("max_outstanding_recon_req", po::value<int>()->default_value(100))
        ("sks_bitstring", po::value<int>()->default_value(0))
        ("async_timeout_sec", po::value<int>()->default_value(1))
        ("async_timeout_usec", po::value<int>()->default_value(0))
    ;
    generic_config.add_options()
        ("debug", po::value<int>()->default_value(5))
        ("version", po::value<std::string>()->default_value("1.1.6"))
        ("recon_port", po::value<int>()->default_value(11372))
        ("http_port", po::value<int>()->default_value(11373))
        ("pks_bind_ip", po::value<std::string>()->default_value("127.0.0.1"))
        ("filters", po::value<std::string>()->default_value("yminsky.dedup,yminsky.merge"))
        ("name", po::value<std::string>()->default_value("peaks_recon"))
        ("gossip_interval", po::value<int>()->default_value(60))
        ("unpack_interval", po::value<int>()->default_value(60))
        ("analyze_interval", po::value<int>()->default_value(60))
        ("max_unpacker_limit", po::value<int>()->default_value(10000))
        ("max_analyzer_limit", po::value<int>()->default_value(10000))
    ; 
    db_config.add_options()
        ("db_host", po::value<std::string>()->default_value("127.0.0.1"))
        ("db_port", po::value<int>()->default_value(3306))
        ("db_user", po::value<std::string>()->default_value("root"))
        ("db_database", po::value<std::string>()->default_value("gpg_keyserver"))
        ("db_password", po::value<std::string>()->default_value(""))
        ("filestorage_format", po::value<std::string>()->default_value("/tmp/peaks_filestorage"))
        ("filestorage_maxsize", po::value<int>()->default_value(100))
        ("expire_interval", po::value<int>()->default_value(15));
    folder_config.add_options()
        ("membership_config", po::value<std::string>()->default_value("/etc/peaks/memebership"))
        ("default_dump_path", po::value<std::string>()->default_value("/tmp/pgp_dump"))
        ("tmp_folder", po::value<std::string>()->default_value("/tmp/peaks_tmp"))
        ("error_folder", po::value<std::string>()->default_value("/tmp/peaks_errors"))
        ;

    dump_desc.add_options()
        ("threads,t", po::value<int>(), "set number of threads")
        ("outdir,o", po::value<std::string>(), "set output dir")
        ;
    
    import_desc.add_options()
        ("init", po::value<std::string>(), "Before loading keys initalize DB using specified file")
        ("threads,t", po::value<int>(), "set number of threads")
        ("path,p", po::value<std::string>(), "path to the dump")
        ("csv-only", po::bool_switch()->default_value(false), "stop certificate import after creating csv")
        ("import-only", po::bool_switch()->default_value(false),"start certificate import directly inserting csv into db")
        ("noclean,n", po::bool_switch()->default_value(false), "do not clean temporary folder")
        ;

    unpack_desc.add_options()
        ("threads,t", po::value<int>(), "set number of threads")
        ("limit,l", po::value<int>(), "set limit to how many keys to unpack per run")
        ("csv-only", po::bool_switch()->default_value(false), "stop certificate import after creating csv")
        ("recover", po::bool_switch()->default_value(false), "recover")
        ("reset", po::bool_switch()->default_value(false), "reset")
        ;

    analyzer_desc.add_options()
        ("threads,t", po::value<int>(), "set number of threads")
        ("limit,l", po::value<int>(), "set limit to how many keys to unpack per run")
        ;

    recon_desc.add_options()
        ("server-only", po::bool_switch()->default_value(false), "start only sever part of recon")
        ("client-only", po::bool_switch()->default_value(false), "start only client part of recon")
        ("dryrun", po::bool_switch()->default_value(false), "dryrun")
        ;

}

Context& Context::context(){
    static Context instance;
    return instance;
}

void Context::setContext(const po::variables_map & _vm){
    vm = _vm;
    dbsettings = {
        vm["db_user"].as<std::string>(),
        vm["db_password"].as<std::string>(),
        vm["db_host"].as<std::string>(),
        vm["db_port"].as<int>(),
        vm["db_database"].as<std::string>(),
        vm["tmp_folder"].as<std::string>(),
        vm["error_folder"].as<std::string>(),
        vm["filestorage_format"].as<std::string>(),
        vm["filestorage_maxsize"].as<int>(),
        vm["expire_interval"].as<int>(),
    };
    P_SKS = NTL::conv<NTL::ZZ>(vm["P_SKS_STRING"].as<std::string>().c_str());
    NTL::ZZ_p::init(P_SKS);
    int num_samples = vm["mbar"].as<int>() + 1;
    std::vector<NTL::ZZ_p> points = Utils::Zpoints(num_samples);

    treesettings = {
        vm["mbar"].as<int>(),
        vm["bq"].as<int>(),
        vm["max_ptree_nodes"].as<int>(),
        vm["ptree_thresh_mult"].as<int>(),
        num_samples,
        points,
        vm["ptree_thresh_mult"].as<int>() * vm["mbar"].as<int>(), // split_threshold
        vm["ptree_thresh_mult"].as<int>() * vm["mbar"].as<int>() / 2, // join_threashold
        vm["sks_bitstring"].as<int>(),
    };
    connsettings = {
        vm["version"].as<std::string>(),
        vm["http_port"].as<int>(),
        vm["filters"].as<std::string>(),
        1 << vm["max_read_len_shift"].as<int>(), //1 << 24 max_read_len
        vm["async_timeout_sec"].as<int>(),
        vm["async_timeout_usec"].as<int>()
    };

    msgsettings = {
        vm["P_SKS_STRING"].as<std::string>(),
        NTL::NumBytes(CONTEXT.P_SKS), // 17
        vm["max_request_queue_len"].as<int>(),
    };

    peersettings = {
        vm["membership_config"].as<std::string>(),
        vm["recon_port"].as<int>(),
        vm["request_chunk_size"].as<int>(),
        vm.count("dryrun"),
        msgsettings.sks_zp_bytes - 1, // 16
        vm["max_outstanding_recon_req"].as<int>(),
        vm["gossip_interval"].as<int>(),
        vm["max_recover_size"].as<int>()
    };


}

std::string Context::init_options(int argc, char* argv[]){
    po::positional_options_description pos;
    pos.add("command", 1).add("subargs", -1);

    vm.clear();
    
    po::parsed_options parsed = po::command_line_parser(argc, argv).options(global).positional(pos).allow_unregistered().run();
    
    po::store(parsed, vm);
 
    std::vector<std::string> filenames;
    if (vm.count("config"))
        filenames.insert(filenames.begin(), vm["config"].as<std::string>());
    filenames.push_back("peaks_config");
    filenames.push_back("/var/lib/peaks/peaks_config");
    filenames.push_back("/etc/peaks/peaks_config");
    
    bool parsed_config = false;
    for (const auto &filename: filenames){
       std::cerr << "searching config file " << filename << std::endl;
       std::ifstream cFile(filename);
       if (cFile.is_open()){
           parse_config(cFile, vm);
           parsed_config = true;
           break;
       }
    }
    
   if (parsed_config){
        std::cerr << "config file found!" << std::endl;
    }
    else{
        std::cerr << "config file NOT found! Proceeding with default options" << std::endl;
        std::istringstream empty("");
        parse_config(empty, vm);
    }
    setContext(vm);
    

    std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
    if (!opts.size()) return "help";
    opts.erase(opts.begin());
    po::store(po::command_line_parser(opts).options(import_desc).run(), vm);
    po::notify(vm); // throws on error, so do after help in case of problems
 
    if (vm.count("help")) return "help";
    int log_option;
    int log_upto;
    
    if (vm.count("stdout")){
        std::cerr << "logging to stdout" << std::endl;
        log_option = LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID;
    }
    else{
        log_option = LOG_PID;
    }
    log_upto = LOG_UPTO(vm["debug"].as<int>());
 
    std::string cmd = vm["command"].as<std::string>();
    std::string logname = "peaks" + cmd;
    openlog(logname.c_str(), log_option, LOG_USER);
    setlogmask(log_upto);
    return cmd;
   }
   
   void Context::write_config(){
        po::options_description minimal("Minimal config");
        minimal.add(generic_config).add(db_config).add(folder_config);
        std::ifstream empty;
        po::variables_map vm;
        po::store(po::parse_config_file(empty, minimal, true), vm);
        for (const auto &it: vm){
            std::cout << it.first << " = ";
            if (auto p = boost::any_cast<std::string>(&it.second.value())) std::cout << *p;
            if (auto p = boost::any_cast<int>(&it.second.value())) std::cout << *p;
            std::cout << std::endl;
        }
   }
   
   void Context::parse_config(std::istream& conf, po::variables_map &vm){
       po::options_description all("Allowed options");
       all.add(internal_config).add(generic_config).add(db_config).add(folder_config);
       po::store(po::parse_config_file(conf, all, true), vm);
   }

    bool Context::has(const std::string &name){
        auto it = vm.find(name);
        return (it != vm.end());
    }


