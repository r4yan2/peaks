#ifndef RECON_LOGGER_H
#define RECON_LOGGER_H

#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>
#include "exception.h"
#include <string>
#include <mutex>
#include <vector>
#include <ostream>
#include <iterator>
#include <NTL/ZZ_p.h>
#include <syslog.h>

enum class Logger_level {DEBUG=7, INFO=6, WARNING=4, CRITICAL=2};

class Logger{
    private:
        bool verbose;
        std::ofstream logfile;
        std::mutex mu;
    public:
        Logger();
        void init(bool verb, std::string log_to_file);
        ~Logger();
        void log(Logger_level level, std::string what);
        void log_to_file(Logger_level level, std::string what);
        void log(Logger_level level, const std::vector<NTL::ZZ_p> &vec);

};

extern Logger g_logger;
#endif
