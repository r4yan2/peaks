#include <sstream>
#include <dirent.h>
#include <sys/stat.h>
#include <vector>
#include <syslog.h>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <PKA/PKAs.h>
#include <Misc/sigtypes.h>
#include <boost/algorithm/string.hpp>
#include <regex>

#include "utils.h"

using namespace boost::filesystem;
using namespace std;
using namespace OpenPGP;

namespace peaks{
namespace common{
namespace Utils{

    string get_file_name(const std::string &folder_name, const std::string &name){
		return folder_name + name;
    }

    string get_file_name(const std::string &folder_name, const unsigned int &i){
		return folder_name + FILENAME.at(i);
    }

    string get_file_name(const std::string &folder_name, const unsigned int &i, const thread::id &ID){
        stringstream t_id;
        t_id << ID << "_";
        return folder_name + t_id.str() + FILENAME.at(i);
	}

    int create_folders(const std::string &folder_name){
        boost::system::error_code returnedError;

        create_directories( folder_name, returnedError );

        if ( returnedError ){
            return -1;  // did not successfully create directories
        }
        else{
            return 0;
        }
    }

    /*
    void sort_csv(const std::string & filename){
        ifstream icsv(filename);
        map<pair<string, string>, string> content;
        string line;
        
        while (getline(icsv,line)){
            vector<string> vec
            boost::algorithm::split(vec, line, boost::is_any_of(','));
            map.insert(make_pair(vec.begin(), vec.begin()+1), line);
        }
        icsv.close();

        ofstream ocsv(filename);
        for (auto const & x : content){
            ocsv << x.second
        }
        
    */
    void put_in_error(const std::string &folder_name, const string &f, const unsigned int &i){
        try{
            std::ofstream error_file;
            std::ifstream actual_file;
            error_file.open(folder_name + "Errors" + FILENAME.at(i), ios_base::app);
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
                copy_file(f, folder_name + rnd_num + FILENAME.at(i), copy_option::fail_if_exists);
            }catch (error_code &e){
                syslog(LOG_CRIT, "Saving errors during CSV insertion FAILED, data will be lost! - %s", e.message().c_str());
            }
        }
    }

    int get_files_number(const std::string & folder_name){
        int count=0;
        directory_iterator end_itr;
        for (directory_iterator itr(folder_name); itr != end_itr; ++itr)
        {
            if (is_regular_file(itr->path())) {
                count += 1;
            }
        }
        return count;
    }

    vector<string> get_files(const std::string &folder_name, const unsigned int &i){
        directory_iterator end_itr;
        vector<string> file_list;

        // cycle through the directory
        for (directory_iterator itr(folder_name); itr != end_itr; ++itr)
        {
            // If it's not a directory, list it. If you want to list directories too, just remove this check.
            if (is_regular_file(itr->path()) && hasEnding(itr->path().string(), FILENAME.at(i))) {
                // assign current file name to current_file and echo it out to the console.
                string current_file = itr->path().string();
                file_list.push_back(itr->path().string());
                // std::cout << current_file << std::endl;
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

    std::vector<std::string> dirlisting(const std::string &foldername)
    {
        DIR *theFolder = opendir(foldername.c_str());
        struct dirent *next_file;
        char filepath[512];
        std::vector<std::string> files;
    
        while ( (next_file = readdir(theFolder)) != NULL )
        {
            //skipping folders
            if (next_file->d_type == DT_DIR)
                continue;
            // build the path for each file in the folder
            sprintf(filepath, "%s/%s", foldername.c_str(), next_file->d_name);
            files.push_back(std::string(filepath));
        }
        closedir(theFolder);
        return files;
    }

    std::string calculate_hash(const Key::Ptr &k){
        std::string concatenation = concat(get_ordered_packet(k->get_packets()));
        return hexlify(Hash::use(Hash::ID::MD5, concatenation), true);
    }

    PGP::Packets get_ordered_packet(PGP::Packets packet_list){
        sort(packet_list.begin(), packet_list.end(), compare);
        return packet_list;
    }

    bool compare(const Packet::Tag::Ptr &p1, const Packet::Tag::Ptr &p2){
        if (p1->get_tag() == p2->get_tag()){
            return p1->raw() < p2->raw();
        }else{
            return p1->get_tag() < p2->get_tag();
        }
    }

    string concat(const PGP::Packets &packet_list){
        string out = "";
        for (const auto &p: packet_list){
            out += unhexlify(makehex(p->get_tag(), 8));
            out += unhexlify(makehex(p->raw().size(), 8));
            out += p->raw();
        }

        return out;
    }

string toLower(const string& inputString) {
    string lowerString = "";
    for(char c : inputString) {
        lowerString += tolower(c);
    }
    return lowerString;
}

map<string, string> parse(const string& query) {
    map<string, string> data;
    regex pattern("([\\w+%]+)=([^&]*)");
    auto words_begin = sregex_iterator(query.begin(), query.end(), pattern);
    auto words_end = sregex_iterator();

    for (sregex_iterator i = words_begin; i != words_end; i++) {
        string key = (*i)[1].str();
        string value = (*i)[2].str();
        data[key] = value;
    }

    return data;
}

string htmlEscape(const string& data) {
    std::string buffer;
    buffer.reserve(data.size()*1.1);
    for(size_t pos = 0; pos != data.size(); ++pos) {
        switch(data[pos]) {
            case '&':  buffer.append("&amp;");       break;
            case '\"': buffer.append("&quot;");      break;
            case '\'': buffer.append("&apos;");      break;
            case '<':  buffer.append("&lt;");        break;
            case '>':  buffer.append("&gt;");        break;
            default:   buffer.append(&data[pos], 1); break;
        }
    }
    //data.swap(buffer);
    return buffer;
}

bool signature::is_its_revocation(const signature &r_sign) const{
    if (signature::issuingKeyID != r_sign.issuingKeyID || signature::signedKeyID != r_sign.signedKeyID || signature::signedUsername != r_sign.signedUsername){
        return false;
    }
    switch (signature::hex_type){
        case OpenPGP::Signature_Type::GENERIC_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
        case OpenPGP::Signature_Type::PERSONA_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
        case OpenPGP::Signature_Type::CASUAL_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
        case OpenPGP::Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
            return r_sign.hex_type == OpenPGP::Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE;
        case OpenPGP::Signature_Type::SUBKEY_BINDING_SIGNATURE:
        case OpenPGP::Signature_Type::PRIMARY_KEY_BINDING_SIGNATURE:
        case OpenPGP::Signature_Type::SIGNATURE_DIRECTLY_ON_A_KEY:
            return r_sign.hex_type == OpenPGP::Signature_Type::KEY_REVOCATION_SIGNATURE ||
                    r_sign.hex_type == OpenPGP::Signature_Type::SUBKEY_REVOCATION_SIGNATURE;
        default:
            return false;
    }
}

bool signature::operator==(const signature &rhs) const {
    return hex_type == rhs.hex_type &&
           type == rhs.type &&
           issuingKeyID == rhs.issuingKeyID &&
           signedKeyID == rhs.signedKeyID &&
           signedUsername == rhs.signedUsername &&
           creation_time == rhs.creation_time &&
           exp_time == rhs.exp_time &&
           key_exp_time == rhs.key_exp_time &&
           issuingUID == rhs.issuingUID &&
           is_revocation == rhs.is_revocation;
}

bool signature::operator!=(const signature &rhs) const {
    return !(rhs == *this);
}

bool is_substring(const std::string &str1, const std::string &str2){
    int pos = 0;
    return (str1.find(str2, pos) != string::npos);
}

}

}
}
