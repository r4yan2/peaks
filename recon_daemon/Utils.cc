#include "Utils.h"

std::string Utils::marshall_vec_zz_p(std::vector<NTL::ZZ_p> elements){
  std::ostringstream os;
  std::copy(elements.begin(), elements.end()-1, std::ostream_iterator<NTL::ZZ_p>(os, " "));
  os << elements.back();
  return os.str();
}

std::vector<NTL::ZZ_p> Utils::unmarshall_vec_zz_p(std::string blob){
  std::vector<NTL::ZZ_p> elements;
  std::istringstream is(blob);
  NTL::ZZ_p elem;
  while (is >> elem)
      elements.push_back(elem);
  return elements;
}

std::vector<NTL::ZZ_p> Utils::Zpoints(int num_samples){
  std::vector<NTL::ZZ_p> points(num_samples);
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

int Utils::swap(int d){
   int a;
   unsigned char *dst = (unsigned char *)&a;
   unsigned char *src = (unsigned char *)&d;

   dst[0] = src[3];
   dst[1] = src[2];
   dst[2] = src[1];
   dst[3] = src[0];

   return a;
}
