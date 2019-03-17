#include <sstream>
#include <dirent.h>
#include <sys/stat.h>
#include <vector>
#include <syslog.h>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include "utils.h"

using namespace boost::filesystem;
using namespace std;

namespace IMPORT_Utils{
    string get_file_name(const std::string &csv_folder, const unsigned int &i, const thread::id &ID){
        stringstream t_id;
        t_id << ID;
        return csv_folder + t_id.str() + FILENAME.at(i);
    }

    int create_folder(const std::string &folder_name){
        boost::system::error_code returnedError;

		create_directories(folder_name, returnedError );

        if ( returnedError ){
            return -1;  // did not successfully create directories
        }
        else{
            return 0;
            } // directories successfully created
        }

    void put_in_error(const std::string &error_folder, const string &f, const unsigned int &i){
        try{
            std::ofstream error_file;
            std::ifstream actual_file;
            error_file.open(error_folder + string("Errors") + FILENAME.at(i), ios_base::app);
            actual_file.open(f);

            error_file.seekp(0, ios_base::end);
            error_file << actual_file.rdbuf();
            error_file.close();
            actual_file.close();
        }catch (exception &e){
            try{
                boost::random::mt19937 gen(time(0));
                boost::random::uniform_int_distribution<> dist(1000, 10000);

                string rnd_num = to_string(dist(gen));
                copy_file(f, error_folder + rnd_num + FILENAME.at(i), copy_option::fail_if_exists);
            }catch (error_code &e){
                syslog(LOG_CRIT, "Saving errors during CSV insertion FAILED, data will be lost! - %s", e.message().c_str());
            }
        }
    }

    vector<string> get_files(const std::string &tmp_folder, const unsigned int &i){
        directory_iterator end_itr;
        vector<string> file_list;

        for (directory_iterator itr(tmp_folder); itr != end_itr; ++itr){
            if (hasEnding(itr->path().string(), FILENAME.at(i))) {
                string current_file = itr->path().string();
                file_list.push_back(itr->path().string());
            }
        }
        return file_list;
    }

    vector<string> get_dump_files(const path &dump_path){
        directory_iterator end_itr;
        vector<string> file_list;

        // cycle through the directory
        for (directory_iterator itr(dump_path); itr != end_itr; ++itr){
            if (itr->path().extension() == ".pgp") {
                string current_file = itr->path().string();
                file_list.push_back(itr->path().string());
            }
        }
        return file_list;
    }

    string getCurrentTime(){
        time_t rawtime;
        struct tm * timeinfo;
        char buffer[80];

        time (&rawtime);
        timeinfo = localtime(&rawtime);

        strftime(buffer,sizeof(buffer),"%x %X:%t",timeinfo);
        string str(buffer);
        return str;
    }

    bool hasEnding (string const &fullString, string const &ending) {
        if (fullString.length() >= ending.length()) {
            return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
        } else {
            return false;
        }
    }

    void remove_directory_content(const std::string &foldername)
    {
        // These are data types defined in the "dirent" header
        DIR *theFolder = opendir(foldername.c_str());
        struct dirent *next_file;
        char filepath[512];
    
        while ( (next_file = readdir(theFolder)) != NULL )
        {
            // build the path for each file in the folder
            sprintf(filepath, "%s/%s", foldername.c_str(), next_file->d_name);
            remove(filepath);
        }
        closedir(theFolder);
    }
}