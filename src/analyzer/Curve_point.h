#ifndef ANALYZER_CURVE_POINT_H
#define ANALYZER_CURVE_POINT_H


#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include <bits/shared_ptr.h>
#include "Curve.h"
#include "EC_point.h"

namespace peaks{
namespace analyzer{
class Curve_point{
public:
    Curve_point(const NTL::ZZ_p &x, const NTL::ZZ_p &y, const std::shared_ptr<Curve> &c) : x(x), y(y), c(c) {
        //if (NTL::ZZ_p::modulus == c->getP());
    }

    explicit Curve_point(std::shared_ptr<Curve> c) : c(c) {
        //assert(NTL::ZZ_p::modulus == c->getP());
    }

    Curve_point() = default;

    const NTL::ZZ_p &getX() const { return x; }
    const NTL::ZZ_p &getY() const { return y; }

    virtual const std::shared_ptr<Curve> &getCurve() const { return c; }

protected:
    NTL::ZZ_p x, y;
    std::shared_ptr<Curve> c;

};

}
}

#endif //ANALYZER_CURVE_POINT_H
