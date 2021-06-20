#ifndef ANALYZER_EC_POINT_H
#define ANALYZER_EC_POINT_H


#include <ostream>
#include <NTL/ZZ_p.h>
#include "Elliptic_Curve.h"
#include "Curve_point.h"
namespace peaks{
namespace analyzer{
class EC_point: public Curve_point {
public:
    EC_point(const std::pair<NTL::ZZ_p, NTL::ZZ_p> &xy, std::shared_ptr<Elliptic_Curve> &curve);
    EC_point(const NTL::ZZ &x, const NTL::ZZ &y, std::shared_ptr<Elliptic_Curve> &curve);
    EC_point(const NTL::ZZ_p &x, const NTL::ZZ_p &y, std::shared_ptr<Elliptic_Curve> &curve);
    EC_point(const std::string &xy, std::shared_ptr<Elliptic_Curve> &curve);
    EC_point(const long &x, const long &y, std::shared_ptr<Elliptic_Curve> &curve);

    EC_point() = default;


    EC_point(NTL::ZZ_p x, NTL::ZZ_p y, std::shared_ptr<Curve> curve);

    bool operator==(const EC_point &rhs) const;
    bool operator!=(const EC_point &rhs) const;
    EC_point &operator=(const EC_point& other);
    EC_point operator+(const EC_point &p) const;
    EC_point operator*(const NTL::ZZ &p) const;

    friend std::ostream &operator<<(std::ostream &os, const EC_point &point);

    bool onItsCurve();

    //const std::shared_ptr<Curve> &getCurve() const override;

};

}
}
#endif //ANALYZER_EC_POINT_H
