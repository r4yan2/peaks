#ifndef _PEAKS_GENERIC_CONFIG
#define _PEAKS_GENERIC_CONFIG

#include <atomic>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

namespace peaks{
    class Context {
        public:
	        po::variables_map vm;
            std::atomic<bool> quitting;
            static Context& context();
            Context(Context const &) = delete;
            void operator=(Context const &) = delete;
        private:
            Context(){}
    };
}

#endif
