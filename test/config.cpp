#include "common.h"
#include <NTL/ZZ_p.h>
#include <common/config.h>

BOOST_AUTO_TEST_SUITE(COMMON_CONFIG)

BOOST_TEST_GLOBAL_FIXTURE( test_global_fixture );

BOOST_AUTO_TEST_CASE( test_config_p_sks )
{
    BOOST_TEST_MESSAGE("test P_SKS");
    BOOST_CHECK_EQUAL(NTL::NumBytes(CONTEXT.P_SKS), 17);
}
BOOST_AUTO_TEST_SUITE_END()
