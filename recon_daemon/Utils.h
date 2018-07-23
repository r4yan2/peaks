#ifndef RECON_UTILS_H
#define RECON_UTILS_H

#include <iostream>
#include <boost/dynamic_bitset.hpp>
#include <sstream>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include <fstream>

/*int create_folder(std::string directory){
  boost::system::error_code returnedError;
  if (boost::filesystem::exists(directory)){
      std::cout << "Directory " << directory << " already exists" << "\n";
    return 1;
  } else {
    boost::filesystem::create_directories(directory, returnedError);  
    if (returnedError) {
        std::cout << "Could not create directory (Maybe you miss the correct access right?)" << "\n";
      return 2;
    }
  }
  return 0;
}

*/
namespace Utils{

/** marshal NTL std::vector into suitable data for database insert */
std::string marshall_vec_zz_p(std::vector<NTL::ZZ_p> elements);

/** unmarshal NTL std::vector coming from a database query */
std::vector<NTL::ZZ_p> unmarshall_vec_zz_p(std::string blob);

/** calculate Zpoints for the current number of samples */
std::vector<NTL::ZZ_p> Zpoints(int num_samples);

/** convert a number in finite field (ZZ_p) into a bitstring representation */
boost::dynamic_bitset<unsigned char> ZZp_to_bitset(NTL::ZZ_p num);

/** generate a random number bounded by max_val */
template<typename I> static I get_random(I max_val){
    return static_cast <I> (rand()) / (static_cast <I> (RAND_MAX/max_val));
}


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

}

#endif
