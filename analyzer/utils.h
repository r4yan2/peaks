#ifndef ANALYZER_Utils_H
#define ANALYZER_Utils_H

#include <vector>
#include <cstring>
#include <thread>
#include <boost/filesystem.hpp>
#include <map>
#include "Config.h"


namespace ANALYZER_Utils{
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

    const unsigned int ANALYZED_PUBKEY      = 1;
    const unsigned int ANALYZED_SIGNATURE   = 2;
    const unsigned int BROKEN_PUBKEY        = 3;
    const unsigned int BROKEN_MODULUS       = 4;
    const unsigned int BROKEN_SIGNATURE     = 5;
    const unsigned int REPEATED_R           = 6;

    const std::map<const unsigned int, std::string> FILENAME{
            std::make_pair(ANALYZED_PUBKEY, "_AnalyzedPubkey.csv"),
            std::make_pair(ANALYZED_SIGNATURE, "_AnalyzedSignatures.csv"),
            std::make_pair(BROKEN_PUBKEY, "_BrokenPubKey.csv"),
            std::make_pair(BROKEN_MODULUS, "_BrokenModulus.csv"),
            std::make_pair(BROKEN_SIGNATURE, "_BrokenSignatures.csv"),
            std::make_pair(REPEATED_R, "_RepeatedR.csv")
    };

    std::string get_file_name(const std::string & folder_name, const unsigned int &i, const std::thread::id &ID);
    int create_folders(const std::string & folder_name);
    void put_in_error(const std::string & folder_name, const std::string &f, const unsigned int &i);
    std::vector<std::string> get_files(const std::string & folder_name, const unsigned int &i);
    bool hasEnding (std::string const &fullString, std::string const &ending);
    std::string getCurrentTime();
}

#endif //UNPACKER_Utils_H
