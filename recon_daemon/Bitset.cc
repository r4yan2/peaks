#include "Bitset.h"

Bitset::Bitset(){
    n_bits = 0;
    bytes.clear();
}

Bitset::Bitset(int nbits){
    n_bits = nbits;
    int bytes_size = (nbits%8 == 0) ? nbits/8 : nbits/8 + 1;
	if (nbits > 0){
    	bytes.resize(bytes_size);
    	bzero(bytes.data(), bytes_size);
	}
}

Bitset::Bitset(const NTL::ZZ_p &num){
    NTL::ZZ znum = NTL::rep(num);
    bytes.resize(NumBytes(znum));
    bzero(bytes.data(), bytes.size());
    n_bits = NumBits(znum);
    /*
    for (int i=0; i<n_bits; i++)
        if (bit(znum, n_bits - i - 1) == 1)
		    set(i);
    */
    BytesFromZZ(bytes.data(), znum, bytes.size());
}

Bitset::Bitset(const bytestype &newbytes){
    n_bits = newbytes.size() * 8;
    bytes = newbytes;
}

Bitset::Bitset(const std::string &bitstring){
    n_bits = bitstring.size();
    int bytes_size = (n_bits%8 == 0) ? n_bits/8 : n_bits/8 + 1;
    bytes.resize(bytes_size);
    bzero(bytes.data(), bytes_size);
    for (int i=0; i<n_bits; i++)
        if (bitstring[i] == '1')
            set(i);
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
    int old_size = bytes.size();
    int new_size = byte_pos;
    if (bit_pos > 0)
        new_size += 1;
    bytes.resize(new_size);
    if (new_size > old_size)
        for (int i=old_size; i<new_size; i++)
            bytes[i] = 0x00;
    if (bit_pos != 0){
        int mask = ~((1 << (8-bit_pos))-1);
        bytes[byte_pos] &= mask;
    }
    n_bits = new_bitsize;
}

bool Bitset::test(int bitpos) const{
    if (bitpos > n_bits){
        syslog(LOG_CRIT, "Required to test a bit (%d) outside the bitstring of size %d", bitpos, n_bits);
        throw std::runtime_error("testing a bit outside the bitstring");
    }
    int byte_pos = bitpos/8;
    int bit_pos = bitpos%8;
    return ((bytes[byte_pos] & (1 << (8 - bit_pos - 1))) != 0);
}

void Bitset::set(int bitpos){
    if (bitpos > n_bits)
        throw std::exception();
    int byte_pos = bitpos/8;
    int bit_pos = bitpos%8;
    bytes[byte_pos] |= (1 << (8 - bit_pos - 1));
}

void Bitset::clear(int bitpos){
    if (bitpos > n_bits)
        throw std::exception();
    int byte_pos = bitpos/8;
    int bit_pos = bitpos%8;
    bytes[byte_pos] &= ~(1 << (8 - bit_pos - 1));
}

std::string Bitset::to_string() const{
    std::ostringstream res;
    for (int i=0; i<n_bits; i++){
        if (test(i))
            res << 1;
        else
            res << 0;
    }
    return res.str();
}
