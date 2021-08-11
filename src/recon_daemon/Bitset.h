#ifndef BITSET_RECON_H
#define BITSET_RECON_H

#include <NTL/ZZ_p.h>
#include <vector>
#include <algorithm>
#include <exception>
#include <sstream>
#include <string>
#include <sys/syslog.h>

namespace peaks{
namespace recon{
typedef std::vector<unsigned char> bytestype;

/** class to manage bitstrings "as sks would", so as bit-strings,
 * with bits appended at the end of the string not at the most
 * significant bit, like the modern bitset libraries would do
 */
class Bitset{
    private:
        /** representation of the bitstring as a unsigned char vector */
        bytestype bytes;

        /** number of bits stored */
        int n_bits;
    public:
        Bitset();

        /** constructor
         * @param nbits number of bits to initialize the array
         */
        explicit Bitset(int nbits);

        /** constructor which initialize the bitstring to the given number
         * @param z bitstring representing number
         */
        explicit Bitset(const NTL::ZZ_p& z);

        /** copy constructior
         * @param newbytes byte vector to represent as bitstring
         */
        explicit Bitset(const bytestype &newbytes);

        /** constructor from string take a string representation of bytes
         * @param bitstring
         */
        explicit Bitset(const std::string &bitstring);

        bool operator<(const Bitset & other);

        /** get the size of the bitstring
         * @return int size of bits of the bitstring
         */
        int size() const;

        /** get the bytes size of the bitstring
         * @return the size of the underlying vector
         */
        int num_blocks() const;

        /** get the underlying vector
         * @return the vector of bytes
         */
        bytestype rep() const;

        /** resize the bitstring
         * @param newsize new size of the bitstring
         */
        void resize(int newsize);

        /** test the given bit
         * @param idx index of the bit to test
         * @return true if bit at given index is 1, false otherwise
         */
        bool test(int idx) const;

        /** Put to 1 the bit at the given index
         * @param bitpos index to toggle
         */
        void set(int bitpos);

        /** Put to 0 the bit at the given index
         * @param bitpos index to toggle
         */
        void clear(int bitpos, bool nothrow=false);

        /**
         * Return a decoded bitstring from a string of 0,1
         * @param string of 0/1 chars
         * @return resulting Bitset
         */
        static Bitset from_string(const std::string &);

        /** Get a string representation of the bitstring as 0,1 sequence
         * @return the string representation
         */
	    static std::string to_string(const Bitset &);

        /** Get a byte string representation
         * @return the representation
         */
	    std::string blob() const;

        /** Get a numeric (int) representation of the bitstring
         * NOTE: the representation is calculated FROM LEFT TO RIGHT, so more
         * like a bigint notation
         * @return the integer representation
         */
        int to_int() const;

        /** Get a slice of the bitstring
         * @param start starting index of the bitstring
         * @param end ending index of the bitstring
         * @return resulting Bitstring
         */
        Bitset slice(int start, int end) const;
};

}
}
#endif
