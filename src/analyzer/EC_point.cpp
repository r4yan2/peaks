#include "EC_point.h"
#include "Math_Support.h"
#include "utils.h"

using namespace NTL;
namespace peaks{
namespace analyzer{
EC_point::EC_point(const std::pair<ZZ_p, ZZ_p> &xy, std::shared_ptr<Elliptic_Curve> &curve) : Curve_point(xy.first, xy.second, curve){
    //ZZ_p::init(curve.getP());
}

EC_point::EC_point(const ZZ_p &x, const ZZ_p &y, std::shared_ptr<Elliptic_Curve> &curve) : Curve_point(x, y, curve) {
    //ZZ_p::init(curve.getP());
}

EC_point::EC_point(const ZZ &x, const ZZ &y, std::shared_ptr<Elliptic_Curve> &curve) : Curve_point(conv<ZZ_p>(x), conv<ZZ_p>(y), curve) {
    //ZZ_p::init(curve.getP());
}

EC_point::EC_point(const long &x, const long &y, std::shared_ptr<Elliptic_Curve> &curve) : Curve_point(conv<ZZ_p>(x), conv<ZZ_p>(y), curve) {
    //ZZ_p::init(curve.getP());
}

EC_point::EC_point(NTL::ZZ_p x, NTL::ZZ_p y, std::shared_ptr<Curve> curve) : Curve_point(x, y, curve){}

EC_point::EC_point(const std::string &xy, std::shared_ptr<Elliptic_Curve> &curve) : Curve_point(curve) {
    ZZ y_p;
    EC_point::x = conv<ZZ_p>(mpitodec(rawtompi(xy.substr(1))).c_str());
    if (hexlify(xy.substr(0,1)) == "02"){
        y_p = ZZ(0);
    }else if (hexlify(xy.substr(0,1)) == "03"){
        y_p = ZZ(1);
    }else{
        throw std::runtime_error("Malformed point");
    }
    ZZ_p alpha = power(EC_point::x, 3) + curve->getA() * EC_point::x + curve->getB();
    ZZ beta = SqrRoot(conv<ZZ>(alpha)) % curve->getP();
    if (y_p == beta % 2){
        EC_point::y = conv<ZZ_p>(beta);
    }else {
        EC_point::y = conv<ZZ_p>(curve->getP() - beta);
    }

}

bool EC_point::operator==(const EC_point &rhs) const {
    return x == rhs.x &&
           y == rhs.y &&
           c == rhs.c;
}

bool EC_point::operator!=(const EC_point &rhs) const {
    return !(rhs == *this);
}

std::ostream &operator<<(std::ostream &os, const EC_point &point) {
    os << "x: " << point.x << " y: " << point.y << "\nCurve: " << point.c;
    return os;
}

EC_point EC_point::operator+(const EC_point &p) const {
    if (p.c != EC_point::c){
        throw std::runtime_error("Sum not possible between two points of different curve");
    }
    ZZ_p lambda = (y - p.y) * power(x - p.x, -1);
    ZZ_p x_3 = power(lambda, 2) - x - p.x;
    ZZ_p y_3 = lambda * (x - x_3) - y;
    return EC_point(x_3, y_3, p.c);
}

EC_point &EC_point::operator=(const EC_point& other){
    if (this != &other) { // self-assignment check expected
        EC_point::x = other.x;
        EC_point::y = other.y;
        EC_point::c = other.c;
    }
    return *this;
}


EC_point EC_point::operator*(const ZZ &n) const {
    if (n == 2){
        std::shared_ptr<Elliptic_Curve> curve = std::dynamic_pointer_cast<Elliptic_Curve>(c);
        ZZ_p lambda = (3 * power(EC_point::x, 2) + conv<ZZ_p>(curve->getA())) * power((2 * EC_point::y), -1);
        ZZ_p x_4 = power(lambda, 2) - 2 * EC_point::x;
        ZZ_p y_4 = -EC_point::y + lambda * (EC_point::x - x_4);
        return EC_point(x_4, y_4, EC_point::c);
    }

    EC_point N = EC_point(EC_point::x, EC_point::y, EC_point::c);
    EC_point P = EC_point(EC_point::x, EC_point::y, EC_point::c);
    for (long i = NumBits(n) - 2; i >= 0; i--){
        P = P * ZZ(2);
        if (bit(n, i) == 1){
            P = P + N;
        }
    }
    return P;
/*
    if (n == 0){
        return EC_point(ZZ_p(0), ZZ_p(0), c); // computation complete
    }
    else if (n == 1){
        return EC_point(x, y, c);
    }
    else if (n % 2 == 1){
        return *this + (*this * (n - 1)); // addition when n is odd
    }
    else {
        return (EC_point(EC_point::x, EC_point::y, EC_point::c) * ZZ(2)) * (n/2); // doubling when n is even
    }*/
}

bool EC_point::onItsCurve() {
    std::shared_ptr<Elliptic_Curve> curve = std::dynamic_pointer_cast<Elliptic_Curve>(c);
    return power(y, 2) == power(x, 3) + curve->getA() * x + curve->getB();
}
}
}
