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
        Bitset(const NTL::ZZ_p&);
        Bitset(const bytestype &newbytes);
        Bitset(const std::string &bitstring);

        int size() const;
        int num_blocks() const;
        bytestype rep() const;

        void resize(int newsize);
        bool test(int idx) const;
        void set(int bitpos);
        void clear(int bitpos);

	    std::string to_string() const;
};

#endif
