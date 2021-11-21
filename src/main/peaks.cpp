#include "peaks.h"
namespace peaks{
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
    std::cout << std::endl;

    std::cout << "  build \t\tBuild the prefix-tree" << std::endl;

    std::cout << std::endl;

    std::cout << "  import \t\tImport certificates into Mysql" << std::endl;
    std::cout << "    --init \tBefore loading keys initalize DB using specified file" << std::endl;
    std::cout << "    --threads \tSet number of threads to use" << std::endl;
    std::cout << "    --keys \t\tSet how many keys a thread has to analyze" << std::endl;
    std::cout << "    --path \t\tSet the path of the dump" << std::endl;
    std::cout << "    --csv-only \t\tonly create temporary csv file, do not import into DB" << std::endl;
    std::cout << "    --import-only \tonly import temporary csv, do not create anything" << std::endl;
    std::cout << "    --noclean \t\tdo not clean temporary folder" << std::endl;

    std::cout << std::endl;

    std::cout << "  dump \t\tDump database into csv files, currently output in MySQL directory" << std::endl;
    std::cout << "    --threads \tSet number of threads to use" << std::endl;

    std::cout << std::endl;

    std::cout << "  unpack \t\tUnpack certificate not analyzer during fastimport" << std::endl;
    std::cout << "    --threads \tSet number of threads to use" << std::endl;
    std::cout << "    --csv-only \t\tonly create temporary csv file, do not import into DB" << std::endl;
    std::cout << "    --keys \t\tSet how many keys a thread has to analyze" << std::endl;
    std::cout << "    --limit \tSet the limit on key to unpack" << std::endl;
    std::cout << "    --recover \tRecover previous broken session only" << std::endl;
    std::cout << "    --reset \tReset DB unpacking status" << std::endl;

    std::cout << std::endl;

    std::cout << "  analyze \t\tPerform security analysis on imported pubkeys" << std::endl;
    std::cout << "    --threads \tSet number of threads to use" << std::endl;
    std::cout << "    --keys \t\tSet how many keys a thread has to analyze" << std::endl;
    std::cout << "    --limit \tSet the limit on key to analyze" << std::endl;

    std::cout << std::endl;

    std::cout << "  recon \t\tStart the recon process" << std::endl;
    std::cout << "    --client-only \tStart only as client" << std::endl;
    std::cout << "    --server-only \tStart only as server" << std::endl;
    std::cout << "    --dryrun \t\tRecon without inserting into DB" << std::endl;

    std::cout << std::endl;
    exit(0);
}

void parse_config(std::istream& conf, po::variables_map &vm){
    po::options_description config("Configuration");
    config.add_options()
        ("mbar", po::value<int>()->default_value(5))
        ("bq", po::value<int>()->default_value(2))
        ("max_ptree_nodes", po::value<int>()->default_value(1000))
        ("ptree_thresh_mult", po::value<int>()->default_value(10))
        ("P_SKS_STRING", po::value<std::string>()->default_value("530512889551602322505127520352579437339"))
        ("reconciliation_timeout", po::value<int>()->default_value(45))
        ("version", po::value<std::string>()->default_value("1.1.6"))
        ("recon_port", po::value<int>()->default_value(11372))
        ("http_port", po::value<int>()->default_value(11373))
        ("pks_bind_ip", po::value<std::string>()->default_value("127.0.0.1"))
        ("filters", po::value<std::string>()->default_value("yminsky.dedup,yminsky.merge"))
        ("name", po::value<std::string>()->default_value("peaks_recon"))
        ("gossip_interval", po::value<int>()->default_value(60))
        ("unpack_interval", po::value<int>()->default_value(60))
        ("analyze_interval", po::value<int>()->default_value(60))
        ("max_read_len_shift", po::value<int>()->default_value(24))
        ("max_recover_size", po::value<int>()->default_value(1500))
        ("default_timeout", po::value<int>()->default_value(300))
        ("max_request_queue_len", po::value<int>()->default_value(60000))
        ("request_chunk_size", po::value<int>()->default_value(100))
        ("max_outstanding_recon_req", po::value<int>()->default_value(100))
        ("sks_bitstring", po::value<int>()->default_value(0))
        ("async_timeout_sec", po::value<int>()->default_value(1))
        ("async_timeout_usec", po::value<int>()->default_value(0))
        ("ignore_known_bug", po::value<int>()->default_value(1))
        ("max_unpacker_limit", po::value<unsigned int>()->default_value(10000))
        ("unpack_on_import", po::value<int>()->default_value(0))

        ("db_host", po::value<std::string>()->default_value("127.0.0.1"))
        ("db_port", po::value<int>()->default_value(3306))
        ("db_user", po::value<std::string>()->default_value("root"))
        ("db_database", po::value<std::string>()->default_value("gpg_keyserver"))
        ("db_password", po::value<std::string>()->default_value(""))
        ("filestorage_format", po::value<std::string>()->default_value("/tmp/peaks_filestorage"))
        ("filestorage_maxsize", po::value<int>()->default_value(100))
        ("expire_interval", po::value<int>()->default_value(15))
        ("membership_config", po::value<std::string>()->default_value("/etc/peaks/memebership"))
        ("cppcms_config", po::value<std::string>()->default_value("/etc/peaks/config.js"))
        ("default_dump_path", po::value<std::string>()->default_value("/tmp/pgp_dump"))
        ("tmp_folder", po::value<std::string>()->default_value("/tmp/peaks_import/"))
        ("error_folder", po::value<std::string>()->default_value("/tmp/peaks_errors/"))
        ;

    po::store(po::parse_config_file(conf, config, true), vm);
    vm.insert(std::make_pair("sks_zp_bytes", po::variable_value(17, false)));
    vm.insert(std::make_pair("hashquery_len", po::variable_value(16, false)));
    vm.insert(std::make_pair("num_samples", po::variable_value(vm["mbar"].as<int>() + 1, false)));
    vm.insert(std::make_pair("split_threshold", po::variable_value(vm["ptree_thresh_mult"].as<int>() * vm["mbar"].as<int>(), false)));
    vm.insert(std::make_pair("join_threshold", po::variable_value(vm["split_threshold"].as<int>() / 2, false)));
    vm.insert(std::make_pair("max_read_len", po::variable_value(1 << vm["max_read_len_shift"].as<int>(), false)));

}
}
