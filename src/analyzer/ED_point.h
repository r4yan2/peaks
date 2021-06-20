#ifndef ANALYZER_ED_POINT_H
#define ANALYZER_ED_POINT_H

#include <utility>
#include <NTL/ZZ_p.h>
#include <common/includes.h>
#include <Hashes/Hashes.h>
#include <ostream>
#include <memory>
#include "Math_Support.h"
#include "Edward_Curve.h"
#include "Curve_point.h"


using namespace NTL;

namespace peaks{
namespace analyzer{
class ED_point: public Curve_point {
private:
    //ZZ_p x, y, z, t;
    ZZ_p z, t;
    //const std::shared_ptr<Edward_Curve> c;

    ZZ recover_x(const ZZ &y, const ZZ &sign);


public:

    ED_point(const std::string &s, std::shared_ptr<Edward_Curve> curve);
    ED_point(const ZZ &x, const ZZ &y, std::shared_ptr<Edward_Curve> curve);
    ED_point(const std::pair<ZZ_p, ZZ_p> &xy, std::shared_ptr<Edward_Curve> curve);
    ED_point(const ZZ_p &x, const ZZ_p &y, const ZZ_p &z, const ZZ_p &t, std::shared_ptr<Edward_Curve> curve);

    ED_point operator+(const ED_point &p);
    ED_point operator*(ZZ s);
    ED_point &operator=(const ED_point &p);
    bool operator==(const ED_point &p) const;

    friend std::ostream &operator<<(std::ostream &os, const ED_point &point);
};

}
}
#endif //ANALYZER_ED_POINT_H
