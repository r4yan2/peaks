#ifndef IMPORT_DBSTRUCT_H
#define IMPORT_DBSTRUCT_H

namespace IMPORT_DBStruct{

    struct gpg_keyserver_data{
        int version = 0;
        std::string ID = "";
        std::string fingerprint = "";
        std::string certificate = "";
        std::string hash = "";
        int error_code = 0;
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
        std::string issuingUsername = "";
        std::string uatt_id = "";
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
        int isRevocable = 1;
        bool isExportable = true;
        int isRevocation = 0;
        int isExpired = 0;
        int isValid = 0;

        /* NON SERVONO ALLA SIGNATURE LE COPIO NELLA SELF-SIGNATURE DOPO AVERLE LETTE */
        int trustLevel = 0;
        int isPrimaryUserId = 0;
        std::string primaryUserId = "";
        std::string userRole = "";
        std::string preferedHash = "";
        std::string preferedCompression = "";
        std::string preferedSymmetric = "";

        bool operator==(const IMPORT_DBStruct::signatures &s2) const{
            return s == s2.s && r == s2.r;
        }
    };

    struct userID{
        std::string ownerkeyID = "";
        std::string fingerprint = "";
        std::string name = "";
    };

    struct userAtt{
        long int id = 0;
        std::string fingerprint = "";
        std::string name = "";
        int encoding = 0;
        std::string image = "";
    };

    struct Unpacker_errors {
        int version = 0;
        std::string fingerprint = "";
        bool modified = false;
        std::vector<std::string> comments = {};
    };
}

#endif //IMPORT_DBSTRUCT_H
