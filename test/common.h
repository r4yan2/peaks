#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
#include <boost/program_options.hpp>
#include <NTL/ZZ_p.h>
#include <sstream>
#include <common/config.h>
#include <vector>
#include <string>

namespace po = boost::program_options;
using namespace peaks;

using namespace NTL;
using namespace boost::unit_test;

struct test_global_fixture{

    test_global_fixture(){
    
      std::istringstream config("");

      std::vector<char*> argv;
      argv.push_back("test");
      argv.push_back(nullptr);
      CONTEXT.init_options(argv.size()-1, argv.data());

    }

    ~test_global_fixture(){}
    
    static po::variables_map vm;
};
