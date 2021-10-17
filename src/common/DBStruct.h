#ifndef COMMON_DBSTRUCT_H
#define COMMON_DBSTRUCT_H

#include <cstring>
#include <NTL/ZZ.h>
#include <vector>

#include <recon_daemon/Bitset.h>

namespace peaks{
namespace common{
namespace DBStruct{

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
        NTL::ZZ e = NTL::ZZ(0);
        NTL::ZZ n = NTL::ZZ(0);
        NTL::ZZ p = NTL::ZZ(0);
        NTL::ZZ q = NTL::ZZ(0);
        NTL::ZZ g = NTL::ZZ(0);
        NTL::ZZ y = NTL::ZZ(0);
        std::string curve = "";
    };

    struct signatures{
        unsigned int id = 0;
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
        std::string rString = "";
        std::string sString = "";
        NTL::ZZ r = NTL::ZZ(0);
        NTL::ZZ s = NTL::ZZ(0);
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
        std::string preferedHash = "";
        std::string preferedCompression = "";
        std::string preferedSymmetric = "";
        NTL::ZZ pk_e = NTL::ZZ(0);
        NTL::ZZ pk_n = NTL::ZZ(0);
        NTL::ZZ pk_p = NTL::ZZ(0);
        NTL::ZZ pk_q = NTL::ZZ(0);
        NTL::ZZ pk_g = NTL::ZZ(0);
        NTL::ZZ pk_y = NTL::ZZ(0);
        std::string pk_curve = "";
        unsigned int pk_status = 0;

        bool operator==(const signatures &s2) const{
            return s == s2.s && r == s2.r;
        }
    };

    struct userID{
        std::string ownerkeyID = "";
        std::string fingerprint = "";
        std::string name = "";
        std::string email = "";
    };

    struct userAtt{
        long int id = 0;
        std::string fingerprint = "";
        std::string name = "";
        int encoding = 0;
        std::string image = "";
    };

    struct KeyStatus{
        unsigned int version = 0;
        std::string fingerprint = "";
        unsigned int vulnerabilityCode = 0;
        std::string vulnerabilityDescription = "";
    };

    struct SignatureStatus{
        unsigned int signature_id = 0;
        unsigned int vulnerabilityCode = 0;
        std::string vulnerabilityDescription = "";
    };

    struct node{
        std::string key;
        int key_size;
        std::vector<NTL::ZZ_p> svalues;
        int num_elements;
        bool leaf;
        std::vector<NTL::ZZ_p> elements;
    };

    struct Unpacker_errors {
        int version = 0;
        std::string fingerprint = "";
        bool modified = false;
        std::vector<std::string> comments = {};
    };
}

}
}
#endif
