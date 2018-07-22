#include "exception.h"

char const * solver_exception::what() const throw(){
    return "low_mbar";
}

char const * interpolation_exception::what() const throw(){
    return "size mismatch";
}

char const * send_message_exception::what() const throw(){
    return "fail during sending!";
}

logger_exception::logger_exception(char const* const message) throw(): std::runtime_error(message){}

char const * logger_exception::what() const throw(){
    return "undefined logger level";
}
