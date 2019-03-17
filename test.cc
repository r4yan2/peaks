#define BOOST_TEST_NO_MAIN
#include <boost/program_options.hpp>
#include <fstream>
#include <string>
#include <iostream>
#include "recon_daemon/pTreeDB.h"
#include <NTL/ZZ_p.h>

#include <boost/test/included/unit_test.hpp>

namespace po = boost::program_options;
using namespace boost::unit_test;

void parse_config(std::string filename, po::variables_map &vm){
    std::ifstream cFile (filename);
    if (cFile.is_open())
    {
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
            ("max_unpacker_limit", po::value<int>())

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

class ptree_test {
    private:
        Ptree tree;
    public:
		ptree_test(const po::variables_map &vm);
		~ptree_test();
		void test_insert();
		void test_remove();
};

class ptree_test_suite : public test_suite {
    public:
        ptree_test_suite(); 
};

static test_suite*
init_unit_test_suite( int argc, char * argv[]) {
    //test_suite* ptree_suite = BOOST_TEST_SUITE("Ptree tests");
    //ptree_suite->add(BOOST_TEST_CASE()); 

    //po::variables_map vm;
    //parse_config( "./peaks_config", vm );

    //boost::shared_ptr<ptree_test> instance( new ptree_test() );
    //test_case* insert_test_case  = BOOST_CLASS_TEST_CASE( &ptree_test::test_insert, instance );
    //test_case* remove_test_case  = BOOST_CLASS_TEST_CASE( &ptree_test::test_remove, instance );

    //remove_test_case->depends_on( insert_test_case );

    framework::master_test_suite().add( new ptree_test_suite() );
    return 0;
}

int main(int argc, char* argv[])
{
    return unit_test_main(init_unit_test_suite, argc, argv);
}

ptree_test::ptree_test(const po::variables_map &vm){

    Recon_DBConfig db_settings = {
        vm["db_host"].as<std::string>(),
        vm["db_user"].as<std::string>(),
        vm["db_password"].as<std::string>(),
        vm["db_database"].as<std::string>(),
        vm["recon_tmp_folder"].as<std::string>()
    };

    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(vm["P_SKS_STRING"].as<std::string>().c_str()));
    std::shared_ptr<Recon_memory_DBManager> dbm = std::make_shared<Recon_memory_DBManager>(db_settings);
    std::vector<NTL::ZZ_p> points = RECON_Utils::Zpoints(vm["num_samples"].as<int>());

    Ptree_config ptree_settings = {
        vm["mbar"].as<int>(),
        vm["bq"].as<int>(),
        vm["max_ptree_nodes"].as<int>(),
        vm["ptree_thresh_mult"].as<int>(),
        vm["num_samples"].as<int>(),
        points,
        vm["split_threshold"].as<int>(),
        vm["join_threshold"].as<int>(),
        vm["sks_bitstring"].as<int>()
    };

    tree = Ptree(dbm, ptree_settings);
    tree.create();
}

ptree_test::~ptree_test(){}

void ptree_test::test_insert()
{
    for (int i=100; i<1100; i++){
        NTL::ZZ_p num(i);
        tree.insert(num);
    }
    BOOST_CHECK_EQUAL( tree.get_node("")->get_num_elements() , 1000 );
}

void ptree_test::test_remove()
{
    for (int i=100; i<1100; i++){
        NTL::ZZ_p num(i);
        tree.remove(num);
    }
    BOOST_CHECK_EQUAL( tree.get_node("")->get_num_elements() , 0 );
}

ptree_test_suite::ptree_test_suite() : test_suite("ptree_test_suite"){
    po::variables_map vm;
    parse_config( "./peaks_config", vm );

    // add member function test cases to a test suite
    boost::shared_ptr<ptree_test> instance( new ptree_test(vm) );

    test_case* insert_test_case  = BOOST_CLASS_TEST_CASE( &ptree_test::test_insert, instance );
    test_case* remove_test_case  = BOOST_CLASS_TEST_CASE( &ptree_test::test_remove, instance );

    remove_test_case->depends_on( insert_test_case );

    add( insert_test_case, 100 );
    add( remove_test_case, 100 );
    }
