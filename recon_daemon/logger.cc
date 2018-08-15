#include "logger.h"

Logger g_logger;

void Logger::init(bool verb){
    verbose = verb;
}

Logger::Logger(){
    logfile.open("logfile.txt", std::ios_base::out | std::ios_base::app);
}

Logger::~Logger(){
    logfile.close();
}

void Logger::log(Logger_level level, std::string what){
    std::string str_level;
    switch (level){
        case Logger_level::DEBUG: {
            if (!verbose)
                return;
            str_level += std::string(" [DEBUG] ");
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
