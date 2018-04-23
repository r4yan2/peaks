#ifndef UNPACKER_DBSTRUCT_H
#define UNPACKER_DBSTRUCT_H

namespace DBStruct{

    struct gpg_keyserver_data{
        int version = 0;
        std::string fingerprint = "";
        std::string certificate = "";
    };

    struct pubkey{
        std::string keyId = "";
        int version = 0;
        std::string fingerprint = "";
        std::string priFingerprint = "";
        int pubAlgorithm = 0;
        std::string creationTime = "";
        std::string expirationTime = "";
        std::vector<std::string> algValue = {"", "", "", "", "", ""}; // E, N, P, Q, G, Y
        std::string curve = "";
    };

    struct signatures{
        unsigned int type = 0;
        unsigned int pubAlgorithm = 0;
        unsigned int hashAlgorithm = 0;
        unsigned int version = 0;
        std::string issuingKeyId = "";
        std::string signedKeyId = "";
        std::string issuingFingerprint = "";
        std::string signedFingerprint = "";
        std::string signedUsername = "";
        std::string regex = "";
        std::string creationTime = "";
        std::string expirationTime = "";
        std::string r = "";
        std::string s = "";
        std::string flags = "";
        std::string hashHeader = "";
        std::string signedHash = "";
        int hashMismatch = 0;
        std::string keyExpirationTime = "";
        int revocationCode = 0;
        std::string revocationReason = "";
        int revocationSigId = 0;
        std::string issuingUID = "";
        std::string uatt_id = "";
        int isRevocable = 1;
        bool isExportable = true;
        int isRevocation = 0;
        int isExpired = 0;
        int isValid = 0;

        /* NON SERVONO ALLA SIGNATURE LE COPIO NELLA SELF-SIGNATURE DOPO AVERLE LETTE */
        int trustLevel = 0;
        std::string preferedHash = "";
        std::string preferedCompression = "";
        std::string preferedSymmetric = "";
        bool isPrimaryUserId = false;

        bool operator==(const DBStruct::signatures &s2) const{
            return s == s2.s && r == s2.r;
        }
    };

    struct userAtt{
        long int id = 0;
        std::string fingerprint = "";
        std::string name = "";
        int encoding = 0;
        std::string image = "";
    };

    struct Unpacker_errors {
        bool modified = false;
        const std::string keyId{};
        std::vector<std::string> comments = {};

        explicit Unpacker_errors(std::string kId) : keyId(kId){}
    };
}

#endif //UNPACKER_DBSTRUCT_H
