#include <common/utils.h>
#include "common.h"

using namespace peaks::common::Utils;

BOOST_AUTO_TEST_SUITE(RECON_UTILS)

BOOST_TEST_GLOBAL_FIXTURE( test_global_fixture );

BOOST_AUTO_TEST_CASE( test_marshall_vec_zz_p )
{
    std::vector<ZZ_p> test_vec;
    for (int i=100; i<105; i++)
        test_vec.push_back(ZZ_p(i));
    std::string result_string = marshall_vec_zz_p(test_vec);
    BOOST_CHECK_EQUAL(result_string, "100 101 102 103 104");
}

BOOST_AUTO_TEST_CASE( test_unmarshall_vec_zz_p )
{
    std::vector<ZZ_p> result_vec = unmarshall_vec_zz_p("100 101 102 103 104");
    for (int i=0; i<5; i++)
        BOOST_CHECK_EQUAL(result_vec[i], ZZ_p(100+i));
}

BOOST_AUTO_TEST_CASE( test_ZZp_to_bitstring )
{
    // 42 in base 10 is 101010 in base 2, but we use a reverse notation
    std::string result_str = ZZp_to_bitstring(ZZ_p(42));
    BOOST_CHECK_EQUAL(result_str, "010101");
}


BOOST_AUTO_TEST_CASE( test_bytes_to_zz )
{
    std::vector<unsigned char> test_vec;
    int test = 42;
    test_vec.push_back((uint8_t) test);
    test_vec.push_back((uint8_t) test>>8);
    test_vec.push_back((uint8_t) test>>16);
    test_vec.push_back((uint8_t) test>>24);
    ZZ_p result_zz = bytes_to_zz(test_vec);
    BOOST_CHECK_EQUAL(result_zz, ZZ_p(42));
}

BOOST_AUTO_TEST_CASE( test_hex_to_zz )
{
    std::string hash = "4fc00a69e4";
    ZZ_p res = hex_to_zz(hash);
    BOOST_CHECK_EQUAL(res, ZZ_p(981014855759));
}

BOOST_AUTO_TEST_CASE( test_zz_to_hex )
{
    std::string result_str_padding2 = zz_to_hex(ZZ_p(42), 2);
    BOOST_CHECK_EQUAL(result_str_padding2, "2a");
    std::string result_str_padding8 = zz_to_hex(ZZ_p(42), 8);
    BOOST_CHECK_EQUAL(result_str_padding8, "2a000000");
    std::string result_str_padding16 = zz_to_hex(ZZ_p(42), 16);
    BOOST_CHECK_EQUAL(result_str_padding16, "2a00000000000000");
    std::string result_str = zz_to_hex(ZZ_p(42));
    BOOST_CHECK_EQUAL(result_str, "2a000000000000000000000000000000");
}

BOOST_AUTO_TEST_CASE( test_swap )
{
    int result = 42;
    int test = 0;
    uint8_t *dst = (uint8_t *) &test;
    dst[0] = (uint8_t) result;
    dst[1] = (uint8_t) result >> 8;
    dst[2] = (uint8_t) result >> 16;
    dst[3] = (uint8_t) result >> 24;
    BOOST_CHECK_EQUAL(result, (int) *dst);
}

BOOST_AUTO_TEST_CASE( test_pop_front )
{
    std::vector<int> test_vec = {1, 2, 3, 4, 5, 6, 7};
    int res_value = pop_front(test_vec);
    std::vector<int> expected_value = {2, 3, 4, 5, 6, 7};
    BOOST_CHECK_EQUAL(res_value, 1);
    BOOST_CHECK_EQUAL_COLLECTIONS(test_vec.begin(), test_vec.end(),
            expected_value.begin(), expected_value.end());
}

BOOST_AUTO_TEST_CASE( test_Zpoints )
{
    int test_samples = 6;
    std::vector<ZZ_p> res_samples = Zpoints(test_samples);
    std::vector<ZZ_p> expected_result = {
        ZZ_p(0),
        ZZ_p(-1),
        ZZ_p(1),
        ZZ_p(-2),
        ZZ_p(2),
        ZZ_p(-3)
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(res_samples.begin(), 
            res_samples.end(),
            expected_result.begin(),
            expected_result.end());
}

BOOST_AUTO_TEST_SUITE_END()
