#include "config.h"
#include <boost/program_options/variables_map.hpp>

using namespace peaks;

Context& Context::context(){
    static Context instance;
    return instance;
}

void Context::setContext(const po::variables_map & _vm){
    vm = _vm;
    dbsettings = {
        vm["db_user"].as<std::string>(),
        vm["db_password"].as<std::string>(),
        vm["db_host"].as<std::string>(),
        vm["db_database"].as<std::string>(),
        vm["tmp_folder"].as<std::string>(),
        vm["error_folder"].as<std::string>()
    };


}
