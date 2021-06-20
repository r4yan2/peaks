#ifndef RECON_UTILS_H
#define RECON_UTILS_H

#include <iostream>
#include <sstream>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include <fstream>
#include <ostream>
#include <vector>
#include <iterator>
#include <algorithm>
#include "Recon_settings.h"
#include <boost/filesystem.hpp>

namespace peaks{
namespace recon{
namespace RECON_Utils{

/** marshal NTL std::vector into suitable data for database insert */
std::string marshall_vec_zz_p(const std::vector<NTL::ZZ_p> &elements);

/** unmarshal NTL std::vector coming from a database query */
std::vector<NTL::ZZ_p> unmarshall_vec_zz_p(const std::string &blob);

/** convert a number in finite field (ZZ_p) into a bitstring representation */
//boost::dynamic_bitset<unsigned char> ZZp_to_bitset(NTL::ZZ_p num);

std::string ZZp_to_bitstring(const NTL::ZZ_p &num);

NTL::ZZ_p bytes_to_zz(const std::vector<unsigned char> &bytes);

/** generate a random number bounded by max_val */
template<typename I> static I get_random(I max_val){
    return static_cast <I> (rand()) / (static_cast <I> (RAND_MAX/max_val));
}

/** calculate ZZ int number from hex representation */
NTL::ZZ_p hex_to_zz(const std::string &hash);

/** generate hex string from ZZ number*/
std::string zz_to_hex(const NTL::ZZ_p &num, size_t padding=32);

/** swap endianess of an int */
int swap(int d);

/** pop from the front of a std::vector */
template<typename T>
T pop_front(std::vector<T>& vec)
{
    assert(!vec.empty());
    T a = vec[0];
    vec.erase(vec.begin());
    return a;
}

int create_folders(const std::string &folder_name);
std::vector<NTL::ZZ_p> Zpoints(int num_samples);
}

}
}

#endif
