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

enum class Logger_level {DEBUG=0, WARNING=1, CRITICAL=2};

class Logger{
    private:
        bool verbose;
        std::ofstream logfile;
        std::mutex mu;
    public:
        Logger();
        void init(bool verb);
        ~Logger();
        void log(Logger_level level, std::string what, bool cont=false);
        template <typename T> void log(std::vector<T> vec);

};

extern Logger g_logger;
#endif
