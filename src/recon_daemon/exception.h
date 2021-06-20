#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <iostream>
#include <exception>

namespace peaks{
namespace recon{

class solver_exception : public std::exception{
    public:
        virtual char const* what() const throw();
};

class interpolation_exception : public std::exception{
    public:
        virtual char const* what() const throw();
};

class low_mbar_exception : public solver_exception{
    public:
        virtual char const* what() const throw();
};

class send_message_exception : public std::exception{
    public:
        virtual char const* what() const throw();
};

class logger_exception : public std::runtime_error{
    public:
        logger_exception(char const* const message) throw();
        virtual char const* what() const throw();
};

class connection_exception: public std::exception{
    public:
        char const* message;
        connection_exception(char const* error);
        char const* what();
};

}
}
#endif
