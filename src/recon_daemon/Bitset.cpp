#include "Bitset.h"

namespace peaks{
namespace recon{

Bitset::Bitset():
    bytes(),
    n_bits()
{}

Bitset::Bitset(int nbits):
    bytes(),
    n_bits(nbits)
{
    int bytes_size;
    if (nbits%8 == 0)
        bytes_size = nbits/8;
    else
        bytes_size = nbits/8 + 1;
    bytes.resize(bytes_size);
    bzero(bytes.data(), bytes_size);
}

Bitset::Bitset(const NTL::ZZ_p &num)
{
    NTL::ZZ znum = NTL::rep(num);
    bytes = bytestype(NTL::NumBytes(znum));
    BytesFromZZ(bytes.data(), znum, bytes.size());
    n_bits = bytes.size()*8;
    //n_bits = NumBits(num.modulus());
}

Bitset::Bitset(const bytestype &newbytes):
    bytes(newbytes),
    n_bits(newbytes.size()*8)
{}

Bitset::Bitset(const std::string & src):
    bytes(src.begin(), src.end()),
    n_bits(bytes.size()*8)
{}

Bitset::Bitset(const std::string &src, const int & size):
    bytes(src.begin(), src.end()),
    n_bits(size)
{}

bool Bitset::operator<(const Bitset & other){
    if (num_blocks() < other.num_blocks())
        return true;
    else if (other.num_blocks() < num_blocks())
        return false;
    for (int i=0; i<num_blocks(); i++){
        if ((uint8_t)bytes[i] >= (uint8_t)other.rep()[i])
            return false;
    }
    return true;
}

int Bitset::size() const{
    return n_bits;
}

int Bitset::num_blocks() const{
    return bytes.size();
}

bytestype Bitset::rep() const{
    return bytes;
}

void Bitset::resize(int new_bitsize){
    int byte_pos = new_bitsize/8;
    int bit_pos = new_bitsize%8;
    int new_size = byte_pos;
    if (bit_pos > 0)
        new_size += 1;
    bytes.resize(new_size);
    int start, end;
    if (new_bitsize > n_bits){
        start = n_bits;
        end = new_bitsize;
    } else {
        start = new_bitsize;
        end = n_bits;
    }
    n_bits = new_bitsize;
    for (int i=start; i<end; i++)
        clear(i, true);
}

bool Bitset::test(int bitpos) const{
    if (bitpos < 0)
        bitpos += n_bits;
    else if (bitpos > n_bits){
        syslog(LOG_CRIT, "Required to test a bit (%d) outside the bitstring of size %d", bitpos, n_bits);
        throw std::runtime_error("testing a bit outside the bitstring");
    }
    int byte_pos = bitpos/8;
    int bit_pos = bitpos%8;
    return ((bytes[byte_pos] & (1 << (8 - bit_pos - 1))) != 0);
}

void Bitset::set(int bitpos){
    if (bitpos < 0)
        bitpos += n_bits;
    else if (bitpos > n_bits)
        throw std::exception();
    int byte_pos = bitpos/8;
    int bit_pos = bitpos%8;
    bytes[byte_pos] |= (1 << (8 - bit_pos - 1));
}

void Bitset::clear(int bitpos, bool nothrow){
    if (bitpos < 0)
        bitpos += n_bits;
    else if ((bitpos > n_bits) and (!nothrow))
        throw std::runtime_error("clearing a bit outside the bitstring");
    int byte_pos = bitpos/8;
    int bit_pos = bitpos%8;
    bytes[byte_pos] &= ~(1 << (8 - bit_pos - 1));
}

Bitset Bitset::from_string(const std::string & bitstring){
    Bitset res;
    res.n_bits = bitstring.size();
    int bytes_size = (res.n_bits%8 == 0) ? res.n_bits/8 : res.n_bits/8 + 1;
    res.bytes.resize(bytes_size);
    bzero(res.bytes.data(), bytes_size);
    for (int i=0; i<res.n_bits; i++)
        if (bitstring[i] == '1')
            res.set(i);
    return res;
}

std::string Bitset::to_string(const Bitset & bitstring){
    std::string res = "";
    for (int i=0; i<bitstring.n_bits; i++)
        res.append( bitstring.test(i) ? "1" : "0" );
    return res;
}

std::string Bitset::blob() const {
    std::string res(bytes.begin(), bytes.end());
    return res;
}

int Bitset::to_int() const{
    int res = 0;
    for (int i=0; i<n_bits; i++){
        if (test(i)) res += 1<<i;
    }
    return res;
}

Bitset Bitset::slice(int start, int end) const{
    Bitset newbs(end-start);
    for (int i=start, j=0; i < end; i++, j++)
        if (test(i)) newbs.set(j);
    return newbs;
}

}
}
