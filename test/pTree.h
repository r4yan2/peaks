#define BOOST_TEST_NO_MAIN
#define BOOST_TEST_NO_LIB
#include <boost/test/unit_test.hpp>
#include "../recon_daemon/pTreeDB.h"
#include <boost/program_options.hpp>
#include <NTL/ZZ_p.h>

using namespace boost::unit_test;
namespace po = boost::program_options;

class ptree_test {
    private:
        Ptree tree;
    public:
		ptree_test(const po::variables_map &vm);
		~ptree_test();
		void test_insert();
		void test_remove();
};

class ptree_test_suite : public test_suite {
    public:
        ptree_test_suite(); 
};

