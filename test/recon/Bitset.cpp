#include <recon_daemon/Bitset.h>
#include "../common.h"

using namespace peaks::recon;

using namespace NTL;
using namespace boost::unit_test;

BOOST_AUTO_TEST_SUITE(RECON_BITSET)

BOOST_TEST_GLOBAL_FIXTURE( test_global_fixture );

BOOST_AUTO_TEST_CASE( test_constructor_0 ){
    //Bitset::Bitset()
    Bitset empty_test;
    BOOST_CHECK_EQUAL(empty_test.size(), 0);
    BOOST_CHECK_EQUAL(empty_test.num_blocks(), 0);
    BOOST_CHECK_EQUAL(Bitset::to_string(empty_test), "");
}

BOOST_AUTO_TEST_CASE( test_constructor_1 ){
    //Bitset::Bitset(int nbits)
    Bitset test_1(16);
    BOOST_CHECK_EQUAL(test_1.size(), 16);
    BOOST_CHECK_EQUAL(Bitset::to_string(test_1), "0000000000000000");
}

BOOST_AUTO_TEST_CASE( test_constructor_2 ){
    //Bitset::Bitset(const NTL::ZZ_p &num)
    Bitset test_2(ZZ_p(42));
    BOOST_CHECK_EQUAL(Bitset::to_string(test_2), "00101010");

    Bitset test_3(ZZ_p(32847));
    BOOST_CHECK_EQUAL(Bitset::to_string(test_3), "0100111110000000");

}

BOOST_AUTO_TEST_CASE( test_constructor_3 ){
    //Bitset::Bitset(const bytestype &newbytes):
    ZZ_p test(999999);
    bytestype test_data(NumBytes(rep(test)));
    BytesFromZZ(test_data.data(), rep(test), test_data.size());
    Bitset test_3(test_data);
    BOOST_CHECK_EQUAL(test_3.size(), test_data.size()*8); 
    BOOST_CHECK_EQUAL(test_3.num_blocks(), test_data.size()); 
    bytestype test_result = test_3.rep();
    BOOST_CHECK_EQUAL_COLLECTIONS(test_result.begin(), test_result.end(), test_data.begin(), test_data.end());
}
 
BOOST_AUTO_TEST_CASE( test_constructor_4 ){
    //Bitset::Bitset(const std::string &bitstring)
    std::string test_bitstring = "101010";
    Bitset test_4(Bitset::from_string(test_bitstring));
    BOOST_CHECK_EQUAL(test_4.size(), 6);
    BOOST_CHECK_EQUAL(test_4.num_blocks(), 1);
    BOOST_CHECK_EQUAL(Bitset::to_string(test_4), test_bitstring);
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

BOOST_AUTO_TEST_CASE( test_set ){
    Bitset test(16);
    BOOST_REQUIRE_EQUAL(test.size(), 16);
    BOOST_REQUIRE_EQUAL(Bitset::to_string(test), "0000000000000000");
    std::vector<int> test_pos = {1,3,5,6};
    for (auto &pos: test_pos)
        test.set(pos);
}

BOOST_AUTO_TEST_CASE( test_clear ){
    ZZ_p num(127); //1111111
    Bitset test(num);
    std::vector<int> test_pos = {1,3,5,6};
    for (auto &pos: test_pos)
        test.clear(pos);
    for (auto &pos: test_pos)
        BOOST_CHECK_EQUAL(test.test(pos), false);
}

BOOST_AUTO_TEST_CASE( test_test ){
    std::string test_str = "10001111000";
    Bitset test(Bitset::from_string(test_str));
    BOOST_CHECK_EQUAL(Bitset::to_string(test), test_str);
    BOOST_CHECK_THROW(test.test(32), std::runtime_error);
    std::map<int, bool> test_pos = {
        {1,false},
        {3,false},
        {5,true},
        {6,true}};
    for (auto it = test_pos.begin(); it != test_pos.end(); it++){
        int pos = it->first;
        bool value = it->second;
        BOOST_CHECK_EQUAL(test.test(pos), value);
    }
}

BOOST_AUTO_TEST_CASE( test_resize_2 ){
    std::string test_str = "10001111000";
    Bitset test(Bitset::from_string(test_str));
    int oldsize = test_str.size();
    int newsize = oldsize + 5;
    BOOST_CHECK_EQUAL(Bitset::to_string(test), test_str);
    test.resize(newsize);
    BOOST_CHECK_EQUAL(test.size(), newsize);
    for (int i=oldsize; i<newsize; i++)
        BOOST_CHECK_EQUAL(test.test(i), false); //all new bits must be set to 0
}

BOOST_AUTO_TEST_SUITE_END()
