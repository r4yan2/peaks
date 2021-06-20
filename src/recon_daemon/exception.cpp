#include "exception.h"


namespace peaks{
namespace recon{

char const * solver_exception::what() const throw(){
    return "generic solver error";
}

char const * interpolation_exception::what() const throw(){
    return "size mismatch";
}

char const * low_mbar_exception::what() const throw(){
    return "low_mbar";
}

char const * send_message_exception::what() const throw(){
    return "fail during sending!";
}

logger_exception::logger_exception(char const* const message) throw(): std::runtime_error(message){}

char const * logger_exception::what() const throw(){
    return "undefined logger level";
}

connection_exception::connection_exception(char const* error){
    message = error;
}

char const * connection_exception::what(){
    return message;
}

}
}
