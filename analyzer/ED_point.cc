#include <cassert>
#include "ED_point.h"

using namespace Math_Support;

/**
 * Create edward point from raw string
 * @param s string of bytes of x
 * @param curve Edward Curve Object
 */
ED_point::ED_point(const std::string &s, std::shared_ptr<Edward_Curve> curve) : Curve_point(curve){
    if (s.size() != 32){
        throw std::runtime_error("Invalid input length for decompression");
    }

    ZZ y = ZZ_from_bytes(s, 32, ENDIAN::LITTLE);
    ZZ sign = RightShift(y, 255);
    y &= LeftShift(ZZ(1), 255) - 1;

    ZZ x = recover_x(y, sign);

    ED_point::x = conv<ZZ_p>(x);
    ED_point::y = conv<ZZ_p>(y);
    ED_point::z = 1;
    ED_point::t = conv<ZZ_p>(x * y);
}

ED_point::ED_point(const ZZ &x, const ZZ &y, std::shared_ptr<Edward_Curve> curve) : Curve_point(conv<ZZ_p>(x), conv<ZZ_p>(y), curve) {
    ED_point::z = ZZ_p(1);
    ED_point::t = ED_point::x * ED_point::y;
}
ED_point::ED_point(const std::pair<ZZ_p, ZZ_p> &xy, std::shared_ptr<Edward_Curve> curve) : Curve_point(xy.first, xy.second, curve){
    ED_point::z = ZZ_p(1);
    ED_point::t = ED_point::x * ED_point::y;
}


ED_point::ED_point(const ZZ_p &x, const ZZ_p &y, const ZZ_p &z, const ZZ_p &t, std::shared_ptr<Edward_Curve> curve) : Curve_point(x, y, curve) {
    ED_point::z = z;
    ED_point::t = t;
}

ZZ ED_point::recover_x(const ZZ &y, const ZZ &sign){
    std::shared_ptr<Edward_Curve> curve = std::dynamic_pointer_cast<Edward_Curve>(c);
    if (y >= curve->getP()){
        throw std::runtime_error("Decoding failed: y >= p");
    }
    ZZ x2 = (power(y, 2) - 1) * PowerMod((conv<ZZ>(curve->getD()) * power(y, 2) + 1) % curve->getP(), -1, curve->getP()) % curve->getP();
    if (x2 == 0){
        if (sign > ZZ(0)) {
            throw std::runtime_error("Decoding failed: x == 0 && sign == 1");
        }
        else{
            return ZZ(0);
        }
    }

    // Compute square root of x2
    ZZ x = PowerMod(x2, (curve->getP() + 3) / 8, curve->getP());
    if ((power(x, 2) - x2) % curve->getP() != 0) {
        x = x * PowerMod(ZZ(2), (curve->getP() - 1)/4, curve->getP()) % curve->getP();
    }
    if ((power(x, 2) - x2) % curve->getP() != 0){
        throw std::runtime_error("Decoding failed: no square root exists for modulo p");
    }

    if ((x & 1) != sign){
        x = c->getP() - x;
    }
    return x;
}

ED_point ED_point::operator+(const ED_point &p){
    std::shared_ptr<Edward_Curve> curve = std::dynamic_pointer_cast<Edward_Curve>(c);
    if (ED_point::c != p.c){
        throw std::runtime_error("Sum not possible between different curve");
    }
    ZZ_p A = (ED_point::y - ED_point::x) * (p.y - p.x);
    ZZ_p B = (ED_point::y + ED_point::x) * (p.y + p.x);
    ZZ_p C = ED_point::t * 2 * curve->getD() * p.t;
    ZZ_p D = ED_point::z * 2 * p.z;
    ZZ_p E = B - A;
    ZZ_p F = D - C;
    ZZ_p G = D + C;
    ZZ_p H = B + A;

    return ED_point(E*F, G*H, F*G, E*H, curve);
}

ED_point &ED_point::operator=(const ED_point &p){
    ED_point::x = p.x;
    ED_point::y = p.y;
    ED_point::z = p.z;
    ED_point::t = p.t;
    ED_point::c = p.c;
    return *this;
}


ED_point ED_point::operator*(ZZ s){
    std::shared_ptr<Edward_Curve> curve = std::dynamic_pointer_cast<Edward_Curve>(c);
    ED_point Q = ED_point(ZZ_p(0), ZZ_p(1), ZZ_p(1), ZZ_p(0), curve); // Neutral element
    ED_point P = ED_point(ED_point::x, ED_point::y, ED_point::z, ED_point::t, curve);
    while (s > 0){
        if ((s & 1) != 0){
            Q = Q + P;
        }
        P = P + P;
        s >>= 1;
    }
    return ED_point(Q.x, Q.y, Q.z, Q.t, curve);
}

bool ED_point::operator==(const ED_point &p) const {
    if (ED_point::c != p.c){
        return false;
    }
    if (x * p.z - p.x * z != 0){
        return false;
    }
    return (y * p.z - p.y * z != 0) == 0;
}

std::ostream &operator<<(std::ostream &os, const ED_point &point) {
    os << "x: " << point.x << " y: " << point.y << " Curve: " << point.c;
    return os;
}
