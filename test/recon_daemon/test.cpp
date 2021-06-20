#include "test.h"

ptree_test::ptree_test(const po::variables_map &vm){

    Recon_DBConfig db_settings = {
        vm["db_host"].as<std::string>(),
        vm["db_user"].as<std::string>(),
        vm["db_password"].as<std::string>(),
        vm["db_database"].as<std::string>(),
        vm["recon_tmp_folder"].as<std::string>()
    };

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

    Ptree tree(dbm, ptree_settings);
}

ptree_test::~ptree_test(){}

void ptree_test::test_insert()
{
    NTL::ZZ_p num(100);
    tree.insert(num);
}

void ptree_test::test_remove()
{
    NTL::ZZ_p num(100);
    tree.remove(num);
}

ptree_test_suite::ptree_test_suite(const po::variables_map &vm) : test_suite("ptree_test_suite"){

        // add member function test cases to a test suite
        boost::shared_ptr<ptree_test> instance( new ptree_test(vm) );

        test_case* insert_test_case  = BOOST_CLASS_TEST_CASE( &ptree_test::test_insert, instance );
        test_case* remove_test_case  = BOOST_CLASS_TEST_CASE( &ptree_test::test_remove, instance );

        remove_test_case->depends_on( insert_test_case );

        add( insert_test_case, 100 );
        add( remove_test_case, 100 );
    }
