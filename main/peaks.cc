#include "peaks.h"

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
    std::cout << "    --threads \tSet number of threads to use" << std::endl;
    std::cout << "    --keys \t\tSet how many keys a thread has to analyze" << std::endl;
    std::cout << "    --path \t\tSet the path of the dump" << std::endl;
    std::cout << "    --csv-only \t\tonly create temporary csv file, do not import into DB" << std::endl;
    std::cout << "    --import-only \tonly import temporary csv, do not create anything" << std::endl;
    std::cout << "    --fastimport \tDo not unpack certificates" << std::endl;
    std::cout << "    --noclean \t\tdo not clean temporary folder" << std::endl;

    std::cout << std::endl;

    std::cout << "  dump \t\tDump database into csv files, currently output in MySQL directory" << std::endl;
    std::cout << "    --threads \tSet number of threads to use" << std::endl;

    std::cout << std::endl;

    std::cout << "  unpack \t\tUnpack certificate not analyzer during fastimport" << std::endl;
    std::cout << "    --threads \tSet number of threads to use" << std::endl;
    std::cout << "    --keys \t\tSet how many keys a thread has to analyze" << std::endl;
    std::cout << "    --limit \tSet the limit on key to unpack" << std::endl;
    std::cout << "    --recover \tRecover previous broken session only" << std::endl;

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
            ("import_tmp_folder", po::value<std::string>())
            ("import_error_folder", po::value<std::string>())
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
