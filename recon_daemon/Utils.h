#ifndef RECON_UTILS_H
#define RECON_UTILS_H

#include <iostream>
#include <boost/dynamic_bitset.hpp>
#include <sstream>
#include <NTL/vector.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>

namespace recon{
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
class Utils{
    public:
static std::string marshall_vec_zz_p(NTL::Vec<NTL::ZZ_p> elements);

static NTL::Vec<NTL::ZZ_p> unmarshall_vec_zz_p(std::string blob);

static NTL::Vec<NTL::ZZ_p> Zpoints(int num_samples);
static boost::dynamic_bitset<unsigned char> ZZp_to_bitset(NTL::ZZ_p num);
};
}
#endif
