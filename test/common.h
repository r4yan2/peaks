#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
#include <boost/program_options.hpp>
#include <main/peaks.h>
#include <NTL/ZZ_p.h>
#include <sstream>
#include <common/config.h>

namespace po = boost::program_options;
using namespace peaks;

using namespace NTL;
using namespace boost::unit_test;

struct test_global_fixture{

    test_global_fixture(){
    
      std::istringstream config("");

      parse_config( config, vm );

      CONTEXT.setContext(vm);

    }

    ~test_global_fixture(){}
    
    static po::variables_map vm;
};
