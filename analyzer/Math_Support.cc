#include <chrono>
#include <cassert>
#include "Math_Support.h"
#include <gmpxx.h>
#include <fstream>

#define MPZ(x) (x).get_mpz_t() // helpful for using mpz_ functions

using namespace NTL;

namespace Math_Support {
    /*
    ZZ decode_little_endian(const std::string &n, const int &bytes){
        ZZ num = ZZ(0);

        for (int i = 0; i < (bytes + 7)/8; i++){
            unsigned int to_dec;
            if (n[i] <= '9' && n[i] >= 0){
                to_dec = n[i] - '0';
            }else if (n[i] <= 'f' && n[i] >= 'a'){
                to_dec = n[i] - 'a';
            }
            num += to_dec << (8 * i);
        }
        return num;
        //return ZZFromBytes(reinterpret_cast<const unsigned char *>(n.c_str()), bytes);
    }*/

    ZZ ZZ_from_bytes(const std::string &s, long n, const int &endian) {
        //const unsigned char *str = reinterpret_cast<const unsigned char *>(s.c_str());
        //return ZZFromBytes(str, n);

        mpz_t x;
        mpz_init(x);
        mpz_import(x, n, -1, 1, endian, 0, s.c_str());
        char* tmp = mpz_get_str (NULL, 10, x);
        std::string num = tmp;
        delete []tmp;
        mpz_clear(x);
        return conv<ZZ>(num.c_str());
    }

    OpenPGP::MPI zz_to_mpi(const NTL::ZZ &n){
        std::stringstream buffer;
        buffer << n;
        return OpenPGP::dectompi(buffer.str());
    }

    std::string zz_to_string(const NTL::ZZ &n){
        std::stringstream buffer;
        buffer << n;
        return buffer.str();
    }

    OpenPGP::MPI zz_to_mpi(const NTL::ZZ_p &n){
        return zz_to_mpi(conv<ZZ>(n));
    }

    std::string zz_to_string(const NTL::ZZ_p &n){
        return zz_to_string(conv<ZZ>(n));
    }

    /**
     * Test roca vulnerability CVE-2017-15361
     * @param mod: Modulo to be tested
     * @return true if modulo is broken
     */
    bool roca_test(const ZZ &mod){
        for (unsigned long i = 0; i < primes.size(); i++) {
            if (((ZZ(1) << conv<unsigned long>(mod % primes[i])) & markers[i]) == ZZ(0)){
                return false;
            }
        }

        return true;
    }

    NTL::ZZ PowerModulo(ZZ b, ZZ &e, ZZ &n)  {
        //ZZ res = ZZ(1);
        for (unsigned long i = 0; i < e; i++){
            b *= b % n;
        }
        return b;
    }
}