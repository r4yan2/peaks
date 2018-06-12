#include "Utils.h"

using namespace recon;
std::string Utils::marshall_vec_zz_p(NTL::Vec<NTL::ZZ_p> elements){
  std::ostringstream os;
  os << elements;
  return os.str();
}

NTL::Vec<NTL::ZZ_p> Utils::unmarshall_vec_zz_p(std::string blob){
  NTL::Vec<NTL::ZZ_p> elements;
  std::istringstream is(blob);
  is >> elements;
  return elements;
}

NTL::Vec<NTL::ZZ_p> Utils::Zpoints(int num_samples){
  NTL::Vec<NTL::ZZ_p> points;
  points.SetLength(num_samples);
  for (int i=0; i<num_samples; i++){
    int val = ((i + 1) / 2) * ((i % 2 == 0) ? 1 : (-1));
    NTL::ZZ_p tmp(val);
    points[i]=tmp;
  }
  return points;
}

boost::dynamic_bitset<unsigned char> Utils::ZZp_to_bitset(NTL::ZZ_p num){
  boost::dynamic_bitset<unsigned char> bs;  
  for (NTL::ZZ tmp(NTL::rep(num)); !(NTL::IsZero(tmp)); tmp/=2) bs.push_back(tmp%2);
  return bs;
}
