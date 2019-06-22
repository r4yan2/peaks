#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
#include <boost/program_options.hpp>
#include "../main/peaks.h"
#include <NTL/ZZ_p.h>
using namespace NTL;
struct test_global_fixture{
    
    test_global_fixture(){

    boost::program_options::variables_map vm;
    parse_config( "./peaks_config", vm );
    ZZ_p::init(conv<ZZ>(vm["P_SKS_STRING"].as<std::string>().c_str()));
    }

    ~test_global_fixture(){}
};

