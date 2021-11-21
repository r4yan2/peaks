#ifndef Utils_H
#define Utils_H

#include <vector>
#include <cstring>
#include <thread>
#include <boost/filesystem.hpp>
#include <map>
#include <OpenPGP.h>
#include <bits/forward_list.h>
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

    namespace ANALYZER_FILES {
        const unsigned int fileNumber           = 6;
        const unsigned int ANALYZED_PUBKEY      = 1;
        const unsigned int ANALYZED_SIGNATURE   = 2;
        const unsigned int BROKEN_PUBKEY        = 3;
        const unsigned int BROKEN_MODULUS       = 4;
        const unsigned int BROKEN_SIGNATURE     = 5;
        const unsigned int REPEATED_R           = 6;

        const std::map<const unsigned int, std::string> FILENAME{
            std::make_pair(ANALYZED_PUBKEY, "AnalyzedPubkey.csv"),
            std::make_pair(ANALYZED_SIGNATURE, "AnalyzedSignatures.csv"),
            std::make_pair(BROKEN_PUBKEY, "BrokenPubKey.csv"),
            std::make_pair(BROKEN_MODULUS, "BrokenModulus.csv"),
            std::make_pair(BROKEN_SIGNATURE, "BrokenSignatures.csv"),
            std::make_pair(REPEATED_R, "RepeatedR.csv")
        };
    };

    const unsigned int fileNumber       = 8;
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
            std::make_pair(UNPACKED, "Unpacked.csv"),
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
     * @param i specific table file instance
     * @param ID id of the current thread
     * @return filename
     */
    std::string get_file_name(const std::string &folder_name, const unsigned int &i);
    std::string get_file_name(const std::string &folder_name, const std::string &name);
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
    std::string calculate_hash(const Key::Ptr &k);
    OpenPGP::PGP::Packets get_ordered_packet(OpenPGP::PGP::Packets packet_list);
    std::string concat(const OpenPGP::PGP::Packets &packet_list);
    bool compare(const OpenPGP::Packet::Tag::Ptr &p1, const OpenPGP::Packet::Tag::Ptr &p2);
    template <typename K, typename V>
    V get(const  std::map <K,V> & m, const K & key, const V & defval ) {
        typename std::map<K,V>::const_iterator it = m.find( key );
        if ( it == m.end() ) {
           return defval;
        }
        return it->second;
    }


    std::string toLower(const std::string& inputString);
    std::map<std::string, std::string> parse(const std::string& query);
    std::string htmlEscape(const std::string& data);
    bool is_substring(const std::string &str1, const std::string &str2);

    // stringFormat uses all char* arguments, and outputs a std::string
    template<typename ... Args>
    std::string stringFormat( const std::string& format, Args ... args ) {
        size_t size = snprintf( nullptr, 0, format.c_str(), args ... ) + 1; // Extra space for '\0'
        std::unique_ptr<char[]> buf( new char[ size ] );
        snprintf( buf.get(), size, format.c_str(), args ... );
        return std::string( buf.get(), buf.get() + size - 1 ); // We don't want the '\0' inside
    }

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
