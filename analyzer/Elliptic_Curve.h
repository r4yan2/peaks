#ifndef ANALYZER_Elliptic_Curve_H
#define ANALYZER_Elliptic_Curve_H


#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <ostream>
#include "Curve.h"

class Elliptic_Curve: public Curve {
public:
    Elliptic_Curve(const std::string &OID);
    Elliptic_Curve() = default;

    const NTL::ZZ &getP() const override;

    const NTL::ZZ &getOrder() const;

    const NTL::ZZ_p &getA() const;

    const std::pair<NTL::ZZ_p, NTL::ZZ_p> &getG() const;

    const NTL::ZZ_p &getB() const;

    friend std::ostream &operator<<(std::ostream &os, const Elliptic_Curve &curve);

private:
    NTL::ZZ p, order;
    NTL::ZZ_p a, b;
    std::pair<NTL::ZZ_p, NTL::ZZ_p> G;
/*
    NTL::ZZ_p getY(const NTL::ZZ_p &x);

    NTL::ZZ_p getX(const NTL::ZZ_p &y);*/
};


#endif //ANALYZER_Elliptic_Curve_H
