#ifndef PEAKS_UTILS_H_
#define PEAKS_UTILS_H_

#include <string>
#include <memory>
#include <map>
#include <bits/forward_list.h>

namespace peaks {
namespace pks{

class Utils {
public:
    static std::string toLower(const std::string& inputString);
    static std::map<std::string, std::string> parse(const std::string& query);
    static std::string htmlEscape(const std::string& data);

    // stringFormat uses all char* arguments, and outputs a std::string
    template<typename ... Args>
    static std::string stringFormat( const std::string& format, Args ... args ) {
        size_t size = snprintf( nullptr, 0, format.c_str(), args ... ) + 1; // Extra space for '\0'
        std::unique_ptr<char[]> buf( new char[ size ] );
        snprintf( buf.get(), size, format.c_str(), args ... );
        return std::string( buf.get(), buf.get() + size - 1 ); // We don't want the '\0' inside
    }
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

#endif // PEAKS_UTILS_H_
