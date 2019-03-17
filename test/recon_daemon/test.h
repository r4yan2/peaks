#ifndef TEST_RECON
#define TEST_RECON
#include <boost/test/unit_test.hpp>
#include <boost/program_options.hpp>
#include "pTreeDB.h"
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
        ptree_test_suite(const po::variables_map &vm ); 
};

#endif
