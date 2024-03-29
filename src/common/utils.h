#ifndef Utils_H
#define Utils_H

#include <vector>
#include <cstring>
#include <thread>
#include <boost/filesystem.hpp>
#include <map>
#include <OpenPGP.h>
#include <bits/forward_list.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include <iterator>
#include <algorithm>
#include <sys/stat.h>

using namespace OpenPGP;

namespace peaks{
namespace common{
namespace Utils{
    const unsigned int MAX_LIMIT = 100000;
    const unsigned int KEY_PER_THREAD_DEFAULT = 100;

    const unsigned int RSA_BREAKABLE_SIZE = 550;
    const unsigned int RSA_UNSAFE_SIZE = 768;
    const unsigned int RSA_ADVISED_SIZE = 2048;
    const unsigned int RSA_MINIMUM_EXP_SIZE = 18;

    const unsigned int ELGAMAL_DSA_SUBGROUP_BREAKABLE_SIZE = 120;
    const unsigned int ELGAMAL_DSA_SUBGROUP_UNSAFE_SIZE = 160;
    const unsigned int ELGAMAL_DSA_SUBGROUP_ADVISED_SIZE = 224;
    const unsigned int ELGAMAL_DSA_GROUP_BREAKABLE_SIZE = 550;
    const unsigned int ELGAMAL_DSA_GROUP_UNSAFE_SIZE = 768;
    const unsigned int ELGAMAL_DSA_GROUP_ADVISED_SIZE = 2048;

    namespace VULN_CODE {
        const unsigned int ERROR = 100;
        const unsigned int OUTDATED_KEY_SIZE            = 1; // check sign yes
        const unsigned int RSA_PRIME_MODULUS            = 2; // check sign yes
        const unsigned int RSA_COMMON_FACTOR            = 3; // check sign yes
        const unsigned int RSA_LOW_FACTOR               = 4; // check sign yes
        const unsigned int RSA_EXP                      = 5; // check sign yes
        const unsigned int RSA_ROCA                     = 6; // check sign yes
        
        const unsigned int DSA_ELGAMAL_P_PRIME          = 7; // check sign no
        const unsigned int DSA_ELGAMAL_Q_PRIME          = 8; // check sign no
        const unsigned int DSA_ELGAMAL_G_GT_1           = 9; // check sign no
        const unsigned int DSA_ELGAMAL_G_SUBGROUP       = 10; // check sign yes
        const unsigned int DSA_P_1_Q_MULTIPLE           = 11; // check sign no
        const unsigned int CURVE_WRONG                  = 12; // check sign no
        const unsigned int CURVE_POINT_NotOnCurve       = 13; // check sign no
        const unsigned int SIGNATURE_MD5_USED           = 21;
        const unsigned int SIGNATURE_WRONG_ALG          = 22;
        const unsigned int SIGNATURE_REPEATED_R         = 23;
        const unsigned int SIGNATURE_WRONG_CHECK        = 24;
        const unsigned int CANNOT_CHECK_SIGNATURE       = 25;
        const unsigned int SIGNATURE_NOT_EXPORTABLE     = 26;
    }

    const std::map <unsigned int, std::string> VULN_NAME = {
            std::make_pair(VULN_CODE::ERROR, "Error in: "),
            std::make_pair(VULN_CODE::OUTDATED_KEY_SIZE, "KeySize too small: "),
            std::make_pair(VULN_CODE::RSA_PRIME_MODULUS, "RSA modulus is prime"),
            std::make_pair(VULN_CODE::RSA_COMMON_FACTOR, "RSA modulus has common factor with another key"),
            std::make_pair(VULN_CODE::RSA_LOW_FACTOR, "RSA modulus has low prime factor: "),
            std::make_pair(VULN_CODE::RSA_EXP, "RSA exponent is too small: "),
            std::make_pair(VULN_CODE::RSA_ROCA, "RSA roca vulnerability found"),
            std::make_pair(VULN_CODE::DSA_ELGAMAL_P_PRIME, "DSA/Elgamal P is not prime"),
            std::make_pair(VULN_CODE::DSA_ELGAMAL_Q_PRIME, "DSA/Elgamal Q is not prime"),
            std::make_pair(VULN_CODE::DSA_ELGAMAL_G_GT_1, "DSA/Elgamal G equals to 1"),
            std::make_pair(VULN_CODE::DSA_ELGAMAL_G_SUBGROUP, "DSA/Elgamal G wrong subgroup"),
            std::make_pair(VULN_CODE::DSA_P_1_Q_MULTIPLE, "DSA p - 1 is not a multiple of q"),
            std::make_pair(VULN_CODE::CURVE_WRONG, "The algorithm doesn't work on this curve"),
            std::make_pair(VULN_CODE::CURVE_POINT_NotOnCurve, "The public key doesn't belong to the curve"),
            std::make_pair(VULN_CODE::SIGNATURE_MD5_USED, "Used MD5 algorithm for hashing"),
            std::make_pair(VULN_CODE::SIGNATURE_WRONG_ALG, "Used a not valid algorithm for sign"),
            std::make_pair(VULN_CODE::SIGNATURE_REPEATED_R, "Found repeated r"),
            std::make_pair(VULN_CODE::SIGNATURE_WRONG_CHECK, "Not valid signature"),
            std::make_pair(VULN_CODE::CANNOT_CHECK_SIGNATURE, "Cannot check signature due to broken key"),
            std::make_pair(VULN_CODE::SIGNATURE_NOT_EXPORTABLE, "Not exportable signature")
    };

    enum ANALYZER_FILES {
        ANALYZED_PUBKEY      = 11,
        ANALYZED_SIGNATURE   = 12,
        BROKEN_PUBKEY        = 13,
        BROKEN_MODULUS       = 14,
        BROKEN_SIGNATURE     = 15,
        REPEATED_R           = 16,
    };

    enum TABLES {
        CERTIFICATE      = 1,
        PUBKEY           = 2,
        SIGNATURE        = 3,
        SELF_SIGNATURE   = 4,
        USER_ATTRIBUTES  = 5,
        UNPACKER_ERRORS  = 6,
        USERID           = 7,
        UNPACKED         = 8,
        PTREE            = 9,
    };

    const std::map<const unsigned int, std::string> TABLENAME{
        std::make_pair(TABLES::CERTIFICATE, "gpg_keyserver"),
        std::make_pair(TABLES::PUBKEY, "Pubkey"),
        std::make_pair(TABLES::SIGNATURE, "Signatures"),
        std::make_pair(TABLES::SELF_SIGNATURE, "selfSignaturesMetadata"),
        std::make_pair(TABLES::USER_ATTRIBUTES, "UserAttribute"),
        std::make_pair(TABLES::UNPACKER_ERRORS, "Unpacker_errors"),
        std::make_pair(TABLES::USERID, "UserID"),
        std::make_pair(TABLES::UNPACKED, "tmp_unpacker"),
        std::make_pair(TABLES::PTREE, "ptree"),
    };
 
    const std::map<const unsigned int, std::string> FILENAME{
        std::make_pair(TABLES::CERTIFICATE, "Certificate.csv"),
        std::make_pair(TABLES::PUBKEY, "PubKey.csv"),
        std::make_pair(TABLES::SIGNATURE, "Signatures.csv"),
        std::make_pair(TABLES::SELF_SIGNATURE, "SelfSignatures.csv"),
        std::make_pair(TABLES::USER_ATTRIBUTES, "UserAtt.csv"),
        std::make_pair(TABLES::UNPACKER_ERRORS, "UnpackerErrors.csv"),
        std::make_pair(TABLES::USERID, "UserID.csv"),
        std::make_pair(TABLES::UNPACKED, "Unpacked.csv"),
        std::make_pair(TABLES::PTREE, "Ptree.csv"),
        std::make_pair(ANALYZER_FILES::ANALYZED_PUBKEY, "AnalyzedPubkey.csv"),
        std::make_pair(ANALYZER_FILES::ANALYZED_SIGNATURE, "AnalyzedSignatures.csv"),
        std::make_pair(ANALYZER_FILES::BROKEN_PUBKEY, "BrokenPubKey.csv"),
        std::make_pair(ANALYZER_FILES::BROKEN_MODULUS, "BrokenModulus.csv"),
        std::make_pair(ANALYZER_FILES::BROKEN_SIGNATURE, "BrokenSignatures.csv"),
        std::make_pair(ANALYZER_FILES::REPEATED_R, "RepeatedR.csv")
    };

    const std::map<int, std::string> algorithms_map{
        {1, "RSA"},
        {2, "RSA (Encrypt Only)"},
        {3, "RSA (Sign Only)"},
        {16, "Elgamal"},
        {17, "DSA"},
        {18, "ECDH"},
        {19, "ECDSA"},
        {20, "Reserved Elgamal"},
        {21, "Reserved DH"},
        {22, "EdDSA"}
    };
    const std::map<int, std::string> vulnerability_map{
        {1, "Small key size"},
        {2, "Modulus is prime"},
        {3, "Modulus has common factor"},
        {4, "Modulus has low prime factor"},
        {5, "Exponent too small"},
        {6, "Roca vulnerability found"},
        {7, "P is not prime"},
        {8, "Q is not prime"},
        {9, "G equals to 1"},
        {10, "G wrong subgroup"},
        {11, "p - 1 is not a multiple of q"},
        {12, "algorithm doesn't work on this curve"},
        {13, "point doesn't belong to the curve"},
        {100, "Missing parameters"},
        {110, "Missing parameters"},
        {112, "Cannot decode point"},
        {113, "Key size 1024"}
    };


    /** @brief construct filename from the parameters 
     * Add together folder_name, i and ID to build the path to the file
     * @param folder_name folder in which the file are located
     * @param name specific table
     * @param ID (optional) id of the current thread
     * @return filename
     */
    std::string get_file_name(const std::string &folder_name, const std::string &name);
    std::string get_file_name(const std::string &folder_name, const std::string &name, const std::thread::id &ID);
    std::string get_file_name(const std::string &folder_name, const int &table);

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
    std::string calculate_hash(const Key::Ptr &k);
    OpenPGP::PGP::Packets get_ordered_packet(OpenPGP::PGP::Packets packet_list);
    std::string concat(const OpenPGP::PGP::Packets &packet_list);
    int char2int(char input);
    void hex2bin(const char* src, char* target);
    NTL::ZZ_p hex2zz(const std::string &hash);
    bool compare(const OpenPGP::Packet::Tag::Ptr &p1, const OpenPGP::Packet::Tag::Ptr &p2);
    
    template <typename K, typename V>
    V get(const  std::map <K,V> & m, const K & key, const V & defval ) {
        typename std::map<K,V>::const_iterator it = m.find( key );
        if ( it == m.end() ) {
           return defval;
        }
        return it->second;
    }

    /** generate a random number bounded by max_val */
    template<typename I> static I get_random(I max_val){
        return static_cast <I> (rand()) / (static_cast <I> (RAND_MAX/max_val));
    }
    
    /** pop from the front of a std::vector */
    template<typename T>
    T pop_front(std::vector<T>& vec)
    {
        assert(!vec.empty());
        T a = vec[0];
        vec.erase(vec.begin());
        return a;
    }

    class ZZpHash {
    public:
        // id is returned as hash function
        size_t operator()(const NTL::ZZ_p& z) const
        {
            NTL::ZZ a = NTL::rep(z);
            return a%SIZE_MAX;
        }
    };
 
    /** marshal NTL std::vector into suitable data for database insert */
    std::string marshall_vec_zz_p(const std::vector<NTL::ZZ_p> &elements);
    
    /** unmarshal NTL std::vector coming from a database query */
    std::vector<NTL::ZZ_p> unmarshall_vec_zz_p(const std::string &blob);
    
    /** convert a number in finite field (ZZ_p) into a bitstring representation */
    //boost::dynamic_bitset<unsigned char> ZZp_to_bitset(NTL::ZZ_p num);
    
    std::string ZZp_to_bitstring(const NTL::ZZ_p &num);
    
    NTL::ZZ_p bytes_to_zz(const std::vector<unsigned char> &bytes);
    
    /** calculate ZZ int number from hex representation */
    NTL::ZZ_p hex_to_zz(const std::string &hash);
    
    /** generate hex string from ZZ number*/
    std::string zz_to_hex(const NTL::ZZ_p &num, size_t padding=32);
    
    /** swap endianess of an int */
    int swap(int d);
    
    std::vector<NTL::ZZ_p> Zpoints(int num_samples);

    std::string toLower(const std::string& inputString);
    std::map<std::string, std::string> parse(const std::string& query);
    std::string htmlEscape(const std::string& data);
    bool is_substring(const std::string &str1, const std::string &str2);
    std::string float_format(double val, int dp);

    // stringFormat uses all char* arguments, and outputs a std::string
    template<typename ... Args>
    std::string stringFormat( const std::string& format, Args ... args ) {
        size_t size = snprintf( nullptr, 0, format.c_str(), args ... ) + 1; // Extra space for '\0'
        std::unique_ptr<char[]> buf( new char[ size ] );
        snprintf( buf.get(), size, format.c_str(), args ... );
        return std::string( buf.get(), buf.get() + size - 1 ); // We don't want the '\0' inside
    }

    inline bool check_file_exists (const std::string& name) {
        struct stat buffer;
        return (stat (name.c_str(), &buffer) == 0);
    }

	inline std::string hexToUll(const std::string &hex) {
        unsigned long long ullKey = std::stoull(hex, nullptr, 16);
        return std::to_string(ullKey);
    }

    class Lazystring {
        private:
            std::function<std::string()> get_f;
            std::string value;
            bool empty_;
            bool init;
        public:
            Lazystring();
            Lazystring(const std::string &);
            Lazystring(const char* init_);
            Lazystring(std::function<std::string()>, const bool);
            void set_f(std::function<std::string()>);
            void set_empty(bool val);
            bool empty() const;
            bool ready() const;
            std::string get();
            friend std::ostream& operator<< (std::ostream& os, const Lazystring& lazy);
    };

    struct signature{
        unsigned int hex_type = 0x00;
        std::string type = "sig";
        std::string issuingKeyID = "";
        std::string signedKeyID = "";
        std::string signedUsername = "";
        std::string creation_time = "";
        std::string exp_time = "";
        std::string key_exp_time = "";
        std::string issuingUID = "";
        bool is_revocation = false;
        std::forward_list<std::string> vulnerabilities;

        bool is_its_revocation(const signature &r_sign) const;

        bool operator==(const signature &rhs) const;

        bool operator!=(const signature &rhs) const;
    };

    struct key{
        std::string bits = "";
        std::string algoChar = "";
        std::string fingerprint = "";
        std::string keyID = "";
        std::string creation_time = "";
        std::forward_list<signature> signatures;
        std::forward_list<std::string> vulnerabilities;
    };
    struct ua{
        const std::string name = "[contents omitted]";
        std::forward_list<signature> signatures;
    };
    struct uid{
        std::string name = "";
        std::string fingerprint = "";
        std::forward_list<signature> signatures;
        std::forward_list<ua> user_attributes;
    };

    struct full_key{
        key Primary_Key;
        std::forward_list<uid> users;
        std::forward_list<key> subkeys;
    };

}

}
}

#endif //Utils_H
