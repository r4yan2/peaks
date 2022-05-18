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
#include <common/config.h>
#include <stddef.h>

#include "utils.h"

using namespace boost::filesystem;
using namespace std;
using namespace OpenPGP;

namespace peaks{
namespace common{
namespace Utils{

    Lazystring::Lazystring():
        value(""),
        empty_(true),
        init(false)
    {}
    Lazystring::Lazystring(const std::string &init_):
        value(init_),
        empty_(init_.empty()),
        init(false)
    {}
    Lazystring::Lazystring(const char* init_):
        value(init_),
        empty_(value.empty()),
        init(false)
    {}
    Lazystring::Lazystring(std::function<std::string()> f_, const bool empty__):
        get_f(f_),
        value(""),
        empty_(empty__),
        init(true)
    {}
    void Lazystring::set_f(std::function<std::string()> get_f_){
        init = true;
        get_f = get_f_;
    }
    void Lazystring::set_empty(bool val){
        empty_ = val;
    }
    bool Lazystring::empty() const{
        return empty_;
    }
    bool Lazystring::ready() const{
        return init;
    }
    std::string Lazystring::get(){
        if (init){
            init = false;
            value = get_f();
            empty_ = value.empty();
        }
        return value;
    }

    std::ostream& operator <<(std::ostream& os, const Lazystring& lazy) {
        return os << const_cast<Lazystring &>(lazy).get();
    }

    string get_file_name(const std::string &folder_name, const std::string &name){
		return folder_name + name;
    }

    string get_file_name(const std::string &folder_name, const std::string &name, const thread::id &ID){
        stringstream t_id;
        t_id << ID << "_";
        return folder_name + t_id.str() + name;
	}

    string get_file_name(const std::string &folder_name, const int &table){
        return folder_name + FILENAME.at(table);
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

//ASCII loockup table
int ASCIIHexToInt[] =
{
    // ASCII
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

char int2hex[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
std::map<char, unsigned char> char2hex = 
{
  {'0', 0x0},
  {'1', 0x1},
  {'2', 0x2},
  {'3', 0x3},
  {'4', 0x4},
  {'5', 0x5},
  {'6', 0x6},
  {'7', 0x7},
  {'8', 0x8},
  {'9', 0x9},
  {'a', 0xa},
  {'b', 0xb},
  {'c', 0xc},
  {'d', 0xd},
  {'e', 0xe},
  {'f', 0xf},
  {'A', 0xa},
  {'B', 0xb},
  {'C', 0xc},
  {'D', 0xd},
  {'E', 0xe},
  {'F', 0xf}
};

std::string marshall_vec_zz_p(const std::vector<NTL::ZZ_p> &elements){
    if (elements.empty()) return "";
    std::ostringstream os;
    std::copy(elements.begin(), elements.end(), std::ostream_iterator<NTL::ZZ_p>(os, " "));
    std::string res(os.str());
    return res.substr(0,res.size() - 1);
}

std::vector<NTL::ZZ_p> unmarshall_vec_zz_p(const std::string &blob){
  NTL::ZZ_p::init(CONTEXT.P_SKS);
  std::vector<NTL::ZZ_p> elements;
  std::istringstream is(blob);
  NTL::ZZ_p elem;
  while (is >> elem)
      elements.push_back(elem);
  return elements;
  /*
    std::vector<NTL::ZZ_p> res;
    if (blob == "")
        return res;
    std::vector<std::string> splitted;
    boost::split(splitted, blob, boost::is_any_of("\t "));
    for (auto str: splitted)
        res.push_back(NTL::conv<NTL::ZZ_p>(NTL::conv<NTL::ZZ>(str.c_str())));
    return res;
    */
}


int char2int(char input)
{
  if(input >= '0' && input <= '9')
    return input - '0';
  if(input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if(input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  throw std::invalid_argument("Invalid input string");
}

// This function assumes src to be a zero terminated sanitized string with
// an even number of [0-9a-f] characters, and target to be sufficiently large
void hex2bin(const char* src, unsigned char* target)
{
  while(*src && src[1])
  {
    *(target++) = char2int(*src)*16 + char2int(src[1]);
    src += 2;
  }
}

NTL::ZZ_p hex2zz(const std::string &hash){
    std::vector<unsigned char> bytes(hash.size()/2, 'a');
    hex2bin(hash.c_str(), bytes.data());
    NTL::ZZ_p el2 = NTL::conv<NTL::ZZ_p>(NTL::ZZFromBytes(bytes.data(), bytes.size()));
    return el2;
}

NTL::ZZ_p hex_to_zz(const std::string &hash){

    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hash.size() / 2; i++) {
      unsigned char b1 = (unsigned char)(char2hex[hash[2*i]] << 4);
      unsigned char b2 = char2hex[hash[2*i+1]];
      bytes.push_back(b1 | b2);
    }
    NTL::ZZ_p el2 = NTL::conv<NTL::ZZ_p>(NTL::ZZFromBytes(bytes.data(), bytes.size()));
    return el2;
}

NTL::ZZ_p bytes_to_zz(const std::vector<unsigned char> &bytes){
    NTL::ZZ_p::init(CONTEXT.P_SKS);
    NTL::ZZ_p elem;
    //std::reverse(bytes.begin(), bytes.end());
    elem = NTL::conv<NTL::ZZ_p>(NTL::ZZFromBytes(bytes.data(), bytes.size()));
    return elem;
}

std::string ZZp_to_bitstring(const NTL::ZZ_p &num){
    std::ostringstream res;
    for (NTL::ZZ tmp(NTL::rep(num)); !(NTL::IsZero(tmp)); tmp/=2) res << (tmp%2);
    return res.str();
}

std::string zz_to_hex(const NTL::ZZ_p &num, size_t padding){
    std::ostringstream os;
    NTL::ZZ n = NTL::rep(num);
    std::vector<unsigned char> p(NumBytes(n));
    BytesFromZZ(p.data(), n, NumBytes(n));
    for (auto elem: p){
        std::ostringstream tmp;
        tmp << std::hex << (int) elem;
        if (tmp.str().size() == 1)
            os << "0";
        os << tmp.str();
    }
    while (os.str().size() < padding)
        os << "0";
    return os.str();
}

int swap(int d){
   int a;
   unsigned char *dst = (unsigned char *)&a;
   unsigned char *src = (unsigned char *)&d;

   dst[0] = src[3];
   dst[1] = src[2];
   dst[2] = src[1];
   dst[3] = src[0];

   return a;
}

std::vector<NTL::ZZ_p> Zpoints(int num_samples){
  std::vector<NTL::ZZ_p> points(num_samples);
  for (int i=0; i<num_samples; i++){
    int val = ((i + 1) / 2) * ((i % 2 == 0) ? 1 : (-1));
    NTL::ZZ_p tmp(val);
    points[i]=tmp;
  }
  return points;
}

std::string float_format(double val, int dp) {
    int charsNeeded = 1 + snprintf(NULL, 0, "%.*f", dp, val);
    char *buffer = (char *) malloc(charsNeeded);
    snprintf(buffer, charsNeeded, "%.*f", dp, val);
    std::string out = std::string(buffer);
    free(buffer);
    return out;
}

}

}
}
