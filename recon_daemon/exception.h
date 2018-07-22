#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <iostream>
#include <exception>

class solver_exception : public std::exception{
    public:
        virtual char const* what() const throw();
};

class interpolation_exception : public std::exception{
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

#endif
