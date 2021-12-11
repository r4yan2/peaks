#include "../common.h"
#include <recon_daemon/pTreeDB.h>
#include <recon_daemon/DBManager.h>

using namespace peaks::recon;
using namespace peaks::common;

BOOST_TEST_GLOBAL_FIXTURE( test_global_fixture );

po::variables_map test_global_fixture::vm;

BOOST_AUTO_TEST_SUITE(RECON_TREE)

struct ptree_fixture{
    ptree_fixture(){

      std::shared_ptr<RECON_DBManager> dbm = std::make_shared<Recon_memory_DBManager>();
      tree.set_db(dbm);
      tree.create();
    }

    ~ptree_fixture(){
    }

    Ptree tree;
};

BOOST_FIXTURE_TEST_SUITE( ptree, ptree_fixture )

BOOST_AUTO_TEST_CASE(ptree_test_create)
{
    BOOST_TEST_MESSAGE( "test create" );
    // the root node should be empty
    BOOST_CHECK_EQUAL( tree.get_node(Bitset())->get_num_elements() , 0 );
    BOOST_CHECK_EQUAL( tree.get_root()->elements().size() , 0 );
}

BOOST_AUTO_TEST_CASE(ptree_test_insert)
{
    BOOST_TEST_MESSAGE( "test insert" );
    for (int i=100; i<1100; i++){
        NTL::ZZ_p num(i);
        tree.insert(num);
    }
    BOOST_CHECK_EQUAL( tree.get_node(Bitset())->get_num_elements() , 1000 );
}

BOOST_AUTO_TEST_CASE(ptree_test_insert_hash)
{
    BOOST_TEST_MESSAGE("test insert hash");
    std::vector<std::string> test_vector = {
        "000002D051097B858E1E04589B3200F5",
        "0000030A302783B168C3E01C688AAC0D",
        "0000031D1E9CBAE7FED390FDAC19B293",
        "0000054BB0A05653D0684EBCD2799EBA",
        "000007EDED8BAB4CF320621A56DA2F90",
        "000009A4ECCDB5EA28EEDCA6BD7F8B0F",
        "000009D84F42673DB71AB316C8D2D929",
        "00000B9BA7B8296AEC0370715C813C30",
        "00000C049313178A42FAA0FC62B40748",
        "00000C2221E60B80EE54B23F80E582D2"
    };
    for (auto const& h: test_vector)
        tree.insert(h);
    std::vector<NTL::ZZ_p> elements_after_insert = tree.get_root()->elements();
    BOOST_CHECK_EQUAL(elements_after_insert.size(), test_vector.size());

}

BOOST_AUTO_TEST_CASE(ptree_test_remove)
{
    BOOST_TEST_MESSAGE( "test remove" );
    for (int i=100; i<1100; i++){
        NTL::ZZ_p num(i);
        tree.insert(num);
    }
    BOOST_REQUIRE_EQUAL( tree.get_node(Bitset())->get_num_elements(), 1000 );
    for (int i=100; i<1100; i++){
        NTL::ZZ_p num(i);
        tree.remove(num);
    }
    BOOST_CHECK_EQUAL( tree.get_node(Bitset())->get_num_elements() , 0 );
}

BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()
