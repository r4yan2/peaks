#include "config.h"
#include <boost/program_options/variables_map.hpp>
#include <common/utils.h>

using namespace peaks;
using namespace peaks::common;

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
    std::vector<NTL::ZZ_p> points = Utils::Zpoints(vm["num_samples"].as<int>());

    treesettings = {
        vm["mbar"].as<int>(),
        vm["bq"].as<int>(),
        vm["max_ptree_nodes"].as<int>(),
        vm["ptree_thresh_mult"].as<int>(),
        vm["num_samples"].as<int>(),
        points,
        vm["split_threshold"].as<int>(),
        vm["join_threshold"].as<int>(),
        vm["sks_bitstring"].as<int>(),
    };
    connsettings = {
        vm["version"].as<std::string>(),
        vm["http_port"].as<int>(),
        vm["filters"].as<std::string>(),
        vm["max_read_len"].as<int>(),
        vm["async_timeout_sec"].as<int>(),
        vm["async_timeout_usec"].as<int>()
    };

    msgsettings = {
        vm["P_SKS_STRING"].as<std::string>(),
        vm["sks_zp_bytes"].as<int>(),
        vm["max_request_queue_len"].as<int>(),
    };

    peersettings = {
        vm["membership_config"].as<std::string>(),
        vm["recon_port"].as<int>(),
        vm["request_chunk_size"].as<int>(),
        vm.count("dryrun"),
        vm["ignore_known_bug"].as<int>(),
        vm["hashquery_len"].as<int>(),
        vm["max_outstanding_recon_req"].as<int>(),
        vm["gossip_interval"].as<int>(),
        vm["max_recover_size"].as<int>()
    };


}
