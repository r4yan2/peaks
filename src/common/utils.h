#ifndef Utils_H
#define Utils_H

#include <vector>
#include <cstring>
#include <thread>
#include <boost/filesystem.hpp>
#include <map>

namespace peaks{
namespace common{
namespace Utils{
    const unsigned int fileNumber       = 7;
    const unsigned int CERTIFICATE      = 1;
    const unsigned int PUBKEY           = 2;
    const unsigned int SIGNATURE        = 3;
    const unsigned int SELF_SIGNATURE   = 4;
    const unsigned int USER_ATTRIBUTES  = 5;
    const unsigned int UNPACKER_ERRORS  = 6;
    const unsigned int USERID           = 7;
    const unsigned int UNPACKED         = 8;

    const std::map<const unsigned int, std::string> FILENAME{
            std::make_pair(CERTIFICATE, "Certificate.csv"),
            std::make_pair(PUBKEY, "PubKey.csv"),
            std::make_pair(SIGNATURE, "Signatures.csv"),
            std::make_pair(SELF_SIGNATURE, "SelfSignatures.csv"),
            std::make_pair(USER_ATTRIBUTES, "UserAtt.csv"),
            std::make_pair(UNPACKER_ERRORS, "UnpackerErrors.csv"),
            std::make_pair(USERID, "UserID.csv"),
            std::make_pair(UNPACKED, "Unpacked.csv")
    };

    /** @brief construct filename from the parameters 
     * Add together folder_name, i and ID to build the path to the file
     * @param folder_name folder in which the file are located
     * @param i specific table file instance
     * @param ID id of the current thread
     * @return filename
     */
    std::string get_file_name(const std::string &folder_name, const unsigned int &i);
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

    /** @brief return all .pgp files
     * @param dump_path location in which search for .pgp files
     * @return vector of filenames
     */
    std::vector<std::string> get_dump_files(const boost::filesystem::path &dump_path);

    /** @brief get current time of the day
     * @return current time as string
     */
    std::string getCurrentTime();

    /** @brief delete content of given directory
     * @param foldername name of the folder to empty
     */
    void remove_directory_content(const std::string &foldername);

    /** @brief list all files in the given folder
     * @param foldername folder on which perform the operation
     * @return vector of strings representing the content of the folder
     */
    std::vector<std::string> dirlisting(const std::string & foldername);

}

}
}

#endif //Utils_H
