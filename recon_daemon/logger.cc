#include "logger.h"

Logger g_logger;

void Logger::init(bool verb, std::string log_to_file){
    verbose = verb;
    if (log_to_file.size() > 0){
        logfile.open(log_to_file, std::ios_base::out | std::ios_base::app);
    }
    else{
        openlog("peaks", LOG_PID, LOG_USER);
        setlogmask (LOG_UPTO (LOG_NOTICE));
    }
}

Logger::Logger(){
}

Logger::~Logger(){
    if (logfile.is_open())
        logfile.close();
    else
        closelog();
}

void Logger::log(Logger_level level, std::string what){
    if (logfile.is_open())
        log_to_file(level, what);
    else
        syslog(int(level), "%s", what.c_str());
}

void Logger::log_to_file(Logger_level level, std::string what){
    std::string str_level;
    switch (level){
        case Logger_level::DEBUG: {
            if (verbose >= 1)
                str_level += std::string(" [DEBUG] ");
            else
                return;
            break;
                                  }
        case Logger_level::INFO: {
            str_level += std::string(" [INFO] ");
            break;
                                  }
        case Logger_level::WARNING: {
            str_level += std::string(" [WARNING] ");
            break;
                                    }
        case Logger_level::CRITICAL: {
            str_level += std::string(" [CRITICAL] ");
            break;
                                     }
        default:
            throw logger_exception(std::to_string(int(level)).c_str());
    }

    std::string str_now;
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    mu.lock(); 
    logfile << std::put_time(&tm, "%Y-%m-%d %H-%M-%S") << str_level << what << std::endl;
    mu.unlock();
}

void Logger::log(Logger_level level, const std::vector<NTL::ZZ_p> &vec){
    switch(level){
        case Logger_level::INFO:
        case Logger_level::WARNING:
        case Logger_level::CRITICAL:
            break;
        case Logger_level::DEBUG: {
            std::ostringstream os;
            std::copy(vec.begin(), vec.end(), std::ostream_iterator<NTL::ZZ_p>(os, " "));
            mu.lock();
            logfile << os.str() << std::endl;
            mu.unlock();
            break;}
    }
}

