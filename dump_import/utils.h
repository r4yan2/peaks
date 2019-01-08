#ifndef DUMPIMPORT_Utils_H
#define DUMPIMPORT_Utils_H

#include <vector>
#include <cstring>
#include <thread>
#include <boost/filesystem.hpp>
#include <map>
#include "Config.h"

namespace DUMP_Utils{
    const unsigned int CERTIFICATE      = 1;
    const unsigned int PUBKEY           = 2;
    const unsigned int SIGNATURE        = 3;
    const unsigned int SELF_SIGNATURE   = 4;
    const unsigned int USERID           = 5;
    const unsigned int USER_ATTRIBUTES  = 6;
    const unsigned int UNPACKER_ERRORS  = 7;
    const unsigned int BROKEN_KEY       = 8;

    const std::map<const unsigned int, std::string> FILENAME{
            std::make_pair(CERTIFICATE, "_Certificate.csv"),
            std::make_pair(PUBKEY, "_PubKey.csv"),
            std::make_pair(SIGNATURE, "_Signatures.csv"),
            std::make_pair(SELF_SIGNATURE, "_SelfSignatures.csv"),
            std::make_pair(USERID, "_UserID.csv"),
            std::make_pair(USER_ATTRIBUTES, "_UserAtt.csv"),
            std::make_pair(UNPACKER_ERRORS, "_UnpackerErrors.csv"),
            std::make_pair(BROKEN_KEY, "_BrokenKey.csv")
    };

    std::string get_file_name(const std::string &csv_folder, const unsigned int &i, const std::thread::id &ID);
    int create_folder(const std::string &folder_name);
    void put_in_error(const std::string &error_folder, const std::string &f, const unsigned int &i);
    std::vector<std::string> get_files(const std::string &tmp_folder, const unsigned int &i);
    std::vector<std::string> get_dump_files(const boost::filesystem::path &dump_path);
    bool hasEnding (std::string const &fullString, std::string const &ending);
    std::string getCurrentTime();
    void remove_directory_content(const std::string &foldername);

/*
    vector<std::string> listFileEndingWith(std::string end);
*/
}

#endif //DUMP_IMPORT_Utils_H
