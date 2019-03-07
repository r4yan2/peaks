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

    /** @brief construct filename from the parameters 
     * Add together folder_name, i and ID to build the path to the file
     * @param folder_name folder in which the file are located
     * @param i specific table file instance
     * @param ID id of the current thread
     * @return filename
     */
    std::string get_file_name(const std::string &folder_name, const unsigned int &i, const std::thread::id &ID);

    /** @brief create folder
     * @param folder_name folder to create
     * @return return code
     */
    int create_folders(const std::string &folder_name);


    void put_in_error(const std::string & folder_name, const std::string &f, const unsigned int &i);

    /** @brief get filename relative to the current session
     * @param folder_name
     * @param i int relative to csv type
     * @return vector of filename(s)
     */
    std::vector<std::string> get_files(const std::string & folder_name, const unsigned int &i);

    /** @brief return files contained in folder
     * @param folder_name folder in which count files
     * @return number of files in folder
     */
    int get_files_number(const std::string & folder_name);

    /** @brief check if fullString ends with ending
     * @param fullString string in which search
     * @param ending string to search in ending
     * @return true if string ends with ending, false otherwise
     */
    bool hasEnding (std::string const &fullString, std::string const &ending);

    /** @brief get current time of the day
     * @return current time as string
     */
    std::string getCurrentTime();

    /** @brief delete content of given directory
     * @param foldername name of the folder to empty
     */
    void remove_directory_content(const std::string &foldername);
/*
    vector<std::string> listFileEndingWith(std::string end);
*/
}

#endif //UNPACKER_Utils_H
