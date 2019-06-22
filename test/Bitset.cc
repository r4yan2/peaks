#include "../recon_daemon/Bitset.h"
#include "common.h"

using namespace NTL;
using namespace boost::unit_test;

BOOST_AUTO_TEST_SUITE(RECON_BITSET)

BOOST_TEST_GLOBAL_FIXTURE( test_global_fixture );

BOOST_AUTO_TEST_CASE( test_constructor ){
    //Bitset::Bitset()
    Bitset empty_test;
    BOOST_CHECK_EQUAL(empty_test.size(), 0);
    BOOST_CHECK_EQUAL(empty_test.num_blocks(), 0);
    BOOST_CHECK_EQUAL(empty_test.to_string(), "");

    //Bitset::Bitset(int nbits)
    Bitset test_1(16);
    BOOST_CHECK_EQUAL(test_1.size(), 16);
    BOOST_CHECK_EQUAL(test_1.to_string(), "0000000000000000");

    //Bitset::Bitset(const NTL::ZZ_p &num)
    Bitset test_2(ZZ_p(42));
    BOOST_CHECK_EQUAL(test_2.size(), 6);
    BOOST_CHECK_EQUAL(test_2.num_blocks(), 1);
    BOOST_CHECK_EQUAL(test_2.to_string(), "101010");

    //Bitset::Bitset(const bytestype &newbytes)
    Bitset test_3;
    
    //Bitset::Bitset(const std::string &bitstring)
    std::string test_bitstring = "101010";
    Bitset test_4(test_bitstring);
    BOOST_CHECK_EQUAL(test_4.size(), 6);
    BOOST_CHECK_EQUAL(test_4.num_blocks(), 1);
    BOOST_CHECK_EQUAL(test_4.to_string(), test_bitstring);
}

BOOST_AUTO_TEST_CASE( test_resize ){
    int start_size = 5;
    int end_size = 42;
    Bitset test(start_size);
    BOOST_REQUIRE_EQUAL(test.size(), start_size);
    BOOST_REQUIRE_EQUAL(test.num_blocks(), start_size/8+1);
    test.resize(end_size);
    BOOST_CHECK_EQUAL(test.size(), end_size);
    BOOST_CHECK_EQUAL(test.num_blocks(), end_size/8+1);
}
BOOST_AUTO_TEST_SUITE_END()
