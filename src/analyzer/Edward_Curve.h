#ifndef ANALYZER_EDWARD_CURVE_H
#define ANALYZER_EDWARD_CURVE_H

#include <NTL/ZZ_p.h>
#include <ostream>
#include "Curve.h"

using namespace NTL;

namespace peaks{
namespace analyzer{
class Edward_Curve: public Curve{
public:
    explicit Edward_Curve(const std::string &OID);
    Edward_Curve() = default;

    const ZZ &getP() const override;

    const ZZ_p &getD() const;

    const ZZ &getQ() const;

    std::pair<ZZ_p, ZZ_p> getG();

    friend std::ostream &operator<<(std::ostream &os, const Edward_Curve &curve);

private:
    ZZ p;
    ZZ_p b;
    ZZ_p c;
    ZZ_p n;
    ZZ_p d;
    ZZ_p a;
    ZZ_p g_y;
    ZZ_p g_x;
    std::pair<ZZ_p, ZZ_p> G;
    ZZ q;
    std::pair<ZZ_p, ZZ_p> B;
    ZZ_p L;

    ZZ recover_x(const ZZ &y, const long &sign);
};

}
}
#endif //ANALYZER_EDWARD_CURVE_H
