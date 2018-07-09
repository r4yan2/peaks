#include "Utils.h"

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

template<typename I> static I Utils::get_random(I max_val){
    return static_cast <I> (rand()) / (static_cast <I> (RAND_MAX/max_val));
}

void Utils::log_to_file(const std::string &text){
    std::ofstream log_file("log.txt", std::ios_base::out | std::ios_base::app);
    log_file << text << "\n";   
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

template<typename T>
T Utils::pop_front(std::vector<T>& vec)
{
    assert(!vec.empty());
    T a = vec[0];
    vec.erase(vec.begin());
    return a;
}

