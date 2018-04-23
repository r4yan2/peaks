#ifndef ANALYZER_CURVE_H
#define ANALYZER_CURVE_H

#include <string>
#include <utility>
#include <memory>

class Curve {
public:
    explicit Curve(std::string OID) : OID(std::move(OID)) {}

    Curve() = default;

    const std::string &getOID() const{ return OID; };
    virtual const NTL::ZZ &getP() const = 0;

    bool operator==(const Curve &rhs) const {
        return OID == rhs.OID;
    }

    bool operator!=(const Curve &rhs) const {
        return !(rhs == *this);
    }

protected:
    const std::string OID;


};


#endif //ANALYZER_CURVE_H
