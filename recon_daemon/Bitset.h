#ifndef BITSET_RECON_H
#define BITSET_RECON_H

#include <NTL/ZZ_p.h>
#include <vector>
#include <algorithm>
#include <exception>
#include <sstream>
#include <string>

typedef std::vector<unsigned char> bytestype;

class Bitset{
    private:
        bytestype bytes;
        int n_bits;
    public:
        Bitset();
        Bitset(int nbits);
        Bitset(NTL::ZZ_p);
        Bitset(bytestype newbytes);
        Bitset(std::string bitstring);

        int size();
        int num_blocks();
        bytestype rep();

        void resize(int newsize);
        bool test(int idx);
        void set(int bitpos);
        void clear(int bitpos);

		std::string to_string();
};

#endif