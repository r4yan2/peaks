#include <PKA/PKAs.h>
#include "Edward_Curve.h"

namespace peaks{
namespace analyzer{
Edward_Curve::Edward_Curve(const std::string &OID) : Curve(OID) {
    if (OID == OpenPGP::PKA::CURVE_OID::ED_255){
        //Edward_Curve::OID = OID;

        Edward_Curve::p = power2_ZZ(255) - 19;
        ZZ_p::init(Edward_Curve::p);
        Edward_Curve::b = ZZ_p(256);
        Edward_Curve::c = ZZ_p(3);
        Edward_Curve::n = ZZ_p(254);
        Edward_Curve::d = conv<ZZ_p>("37095705934669439343138083508754565189542113879843219016388785533085940283555");
        Edward_Curve::a = ZZ_p(-1);
        Edward_Curve::g_y = 4 * power(ZZ_p(5), -1);
        Edward_Curve::g_x = conv<ZZ_p>(recover_x(conv<ZZ>(g_y), 0));
        Edward_Curve::G = std::make_pair(g_x, g_y);
        Edward_Curve::q = power2_ZZ(252) + conv<ZZ>("27742317777372353535851937790883648493");
        Edward_Curve::B = std::make_pair(conv<ZZ_p>("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
                           conv<ZZ_p>("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
        Edward_Curve::L = power(ZZ_p(2), 252) + conv<ZZ_p>("27742317777372353535851937790883648493");
    }
    else{
        throw std::runtime_error("Curve not recognized");
    }
}

ZZ Edward_Curve::recover_x(const ZZ &y, const long &sign){
    if (y >= p){
        throw std::runtime_error("Decoding failed: y >= p");
    }
    ZZ x2 = (power(y, 2) - 1) * PowerMod((conv<ZZ>(d) * power(y, 2) + 1) % p, -1, p) % p;
    if (x2 == 0){
        if (sign) {
            throw std::runtime_error("Decoding failed: x == 0 && sign == 1");
        }
        else{
            return ZZ(0);
        }
    }

    // Compute square root of x2
    ZZ x = PowerMod(x2, (p + 3) / 8, p);
    if ((power(x, 2) - x2) % p != 0) {
        x = x * PowerMod(ZZ(2), (p - 1)/4, p) % p;
    }
    if ((power(x, 2) - x2) % p != 0){
        throw std::runtime_error("Decoding failed: no square root exists for modulo p");
    }

    if ((x & 1) != sign){
        x = p - x;
    }
    return x;
}

const ZZ &Edward_Curve::getP() const {
    return p;
}

const ZZ_p &Edward_Curve::getD() const {
    return d;
}

const ZZ &Edward_Curve::getQ() const {
    return q;
}

std::pair<ZZ_p, ZZ_p> Edward_Curve::getG() {
    return G;
}

std::ostream &operator<<(std::ostream &os, const Edward_Curve &curve) {
    os << "OID: " << curve.OID << " p: " << curve.p << " b: " << curve.b << " c: " << curve.c << " n: " << curve.n
       << " d: " << curve.d << " a: " << curve.a << " g_y: " << curve.G.first << " g_x: " << curve.G.second
       << " q: " << curve.q << " b_x: " << curve.B.first << " b_y: " << curve.B.second << " L: " << curve.L;
    return os;
}

}
}
