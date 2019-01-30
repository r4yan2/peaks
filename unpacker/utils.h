#ifndef UNPACKER_Utils_H
#define UNPACKER_Utils_H


#include "Config.h"
#include <vector>
#include <cstring>
#include <thread>
#include <boost/filesystem.hpp>
#include <map>


namespace UNPACKER_Utils{
    const unsigned int MAX_LIMIT = 100;
    const unsigned int KEY_PER_THREAD_DEFAULT = 2500;

    const unsigned int UNPACKED         = 1;
    const unsigned int PUBKEY           = 2;
    const unsigned int SIGNATURE        = 3;
    const unsigned int SELF_SIGNATURE   = 4;
    const unsigned int USER_ATTRIBUTES  = 5;
    const unsigned int UNPACKER_ERRORS  = 6;
    const unsigned int USERID           = 7;

    const std::map<const unsigned int, std::string> FILENAME{
            std::make_pair(UNPACKED, "_Unpacked.csv"),
            std::make_pair(PUBKEY, "_PubKey.csv"),
            std::make_pair(SIGNATURE, "_Signatures.csv"),
            std::make_pair(SELF_SIGNATURE, "_SelfSignatures.csv"),
            std::make_pair(USER_ATTRIBUTES, "_UserAtt.csv"),
            std::make_pair(UNPACKER_ERRORS, "_UnpackerErrors.csv"),
            std::make_pair(USERID, "_UserID.csv")
    };

    std::string get_file_name(const std::string &folder_name, const unsigned int &i, const std::thread::id &ID);
    int create_folders(const std::string &folder_name);
    void put_in_error(const std::string & folder_name, const std::string &f, const unsigned int &i);
    std::vector<std::string> get_files(const std::string & folder_name, const unsigned int &i);
    bool hasEnding (std::string const &fullString, std::string const &ending);
    std::string getCurrentTime();

/*
    vector<std::string> listFileEndingWith(std::string end);
*/
}

#endif //UNPACKER_Utils_H
