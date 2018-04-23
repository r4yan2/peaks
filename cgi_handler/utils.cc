#include "utils.h"
#include <string>
#include <regex>
#include <iomanip>
#include <Misc/sigtypes.h>

using namespace peaks;
using namespace std;

string Utils::toLower(const string& inputString) {
    string lowerString = "";
    for(char c : inputString) {
        lowerString += tolower(c);
    }
    return lowerString;
}

map<string, string> Utils::parse(const string& query) {
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

string Utils::htmlEscape(const string& data) {
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
