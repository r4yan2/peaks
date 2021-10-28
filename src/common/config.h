#ifndef _PEAKS_GENERIC_CONFIG
#define _PEAKS_GENERIC_CONFIG

#include <atomic>
#include <boost/program_options.hpp>
#include <boost/program_options/variables_map.hpp>
#include "DBManager.h"

namespace po = boost::program_options;

namespace peaks{
    class Context {
        public:
	        po::variables_map vm;
            common::DBSettings dbsettings;
            std::atomic<bool> quitting;
            static Context& context();
            Context(Context const &) = delete;
            void operator=(Context const &) = delete;
            void setContext(const po::variables_map &);
            int filestorage_index;
        private:
            Context(){}
    };
}

#define CONTEXT Context::context()
#endif
