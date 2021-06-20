#include <string>
#include <iostream>
#include <fstream>
#include <boost/program_options.hpp>

namespace peaks{
/** convenient renaming for program_options, totally optional */
namespace po = boost::program_options;

/** help function shows up the help message when command line is incorrect */
void help();

/** function to parse config file
 * @param filename string which hold the name of the config file
 * @param vm variables_map of boost::program_options, because command line by default overrides config file
 */
void parse_config(std::istream&, po::variables_map&);

}
