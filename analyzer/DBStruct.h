#ifndef ANALYZER_DBSTRUCT_H
#define ANALYZER_DBSTRUCT_H

#include <cstring>
#include <NTL/ZZ.h>

namespace ANALYZER_DBStruct{

    struct pubkey{
        unsigned int version = 0;
        std::string fingerprint = "";
        int pubAlgorithm = 0;
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
        unsigned int pubAlgorithm = 0;
        unsigned int hashAlgorithm = 0;
        unsigned int version = 0;
        std::string issuingFingerprint = "";
        std::string signedFingerprint = "";
        NTL::ZZ r = NTL::ZZ(0);
        NTL::ZZ s = NTL::ZZ(0);
        std::string hashHeader = "";
        std::string signedHash = "";
        bool isExportable = true;
        NTL::ZZ pk_e = NTL::ZZ(0);
        NTL::ZZ pk_n = NTL::ZZ(0);
        NTL::ZZ pk_p = NTL::ZZ(0);
        NTL::ZZ pk_q = NTL::ZZ(0);
        NTL::ZZ pk_g = NTL::ZZ(0);
        NTL::ZZ pk_y = NTL::ZZ(0);
        std::string pk_curve = "";
        unsigned int pk_status = 0;
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
}

#endif //ANALYZER_DBSTRUCT_H
