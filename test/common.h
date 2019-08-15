#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
#include <boost/program_options.hpp>
#include "../main/peaks.h"
#include <NTL/ZZ_p.h>
using namespace NTL;
using namespace boost::unit_test;

struct test_global_fixture{

    test_global_fixture(){
    
    std::istringstream config("");

    parse_config( config, vm );

    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(vm["P_SKS_STRING"].as<std::string>().c_str()));

    }

    ~test_global_fixture(){}
    
    static po::variables_map vm;
};
