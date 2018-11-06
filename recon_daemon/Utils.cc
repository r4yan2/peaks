#include "Utils.h"

namespace RECON_Utils{
//ASCII loockup table
int ASCIIHexToInt[] =
{
    // ASCII
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

char int2hex[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

std::string marshall_vec_zz_p(const std::vector<NTL::ZZ_p> &elements){
    if (elements.empty()) return "";
    std::ostringstream os;
    std::copy(elements.begin(), elements.end(), std::ostream_iterator<NTL::ZZ_p>(os, " "));
    std::string res(os.str());
    return res.substr(0,res.size() - 1);
}

NTL::ZZ_p hex_to_zz(const std::string &hash){

    std::vector<unsigned int> inthash;
    for (size_t i=0; i<hash.size(); i+=2)
        inthash.push_back(16 * ASCIIHexToInt[int(hash[i])] + ASCIIHexToInt[int(hash[i+1])]);

    NTL::ZZ_p elem(0);
    std::reverse(inthash.begin(), inthash.end());
    
    if (recon_settings.sks_compliant == 1){
        for (size_t i=0; i < inthash.size(); i++){
            elem = elem * (2<<7) + inthash[i];
        }
    }else{
        for (size_t i=0; i < inthash.size(); i++)
            elem += (2<<(7*i)) * inthash[i];
    }
    return elem;
}

NTL::ZZ_p bytes_to_zz(const std::vector<unsigned char> &bytes){
    NTL::ZZ_p elem;
    //std::reverse(bytes.begin(), bytes.end());

    if (recon_settings.sks_compliant == 1){
        /*
        for (size_t i=0; i < bytes.size(); i++){
            elem = elem * (2<<7) + (uint8_t) bytes[i];
            */
        elem = NTL::conv<NTL::ZZ_p>(NTL::ZZFromBytes(bytes.data(), bytes.size()));
    }else{
        for (size_t i=0; i < bytes.size(); i++)
            elem += (2<<(7*i)) * (uint8_t) bytes[i];
    }
    return elem;

}

std::vector<NTL::ZZ_p> unmarshall_vec_zz_p(const std::string &blob){
  
  std::vector<NTL::ZZ_p> elements;
  std::istringstream is(blob);
  NTL::ZZ_p elem;
  while (is >> elem)
      elements.push_back(elem);
  return elements;
  /*
    std::vector<NTL::ZZ_p> res;
    if (blob == "")
        return res;
    std::vector<std::string> splitted;
    boost::split(splitted, blob, boost::is_any_of("\t "));
    for (auto str: splitted)
        res.push_back(NTL::conv<NTL::ZZ_p>(NTL::conv<NTL::ZZ>(str.c_str())));
    return res;
    */
}

std::vector<NTL::ZZ_p> Zpoints(int num_samples){
  std::vector<NTL::ZZ_p> points(num_samples);
  for (int i=0; i<num_samples; i++){
    int val = ((i + 1) / 2) * ((i % 2 == 0) ? 1 : (-1));
    NTL::ZZ_p tmp(val);
    points[i]=tmp;
  }
  return points;
}

std::string ZZp_to_bitstring(const NTL::ZZ_p &num){
    std::ostringstream res;
    for (NTL::ZZ tmp(NTL::rep(num)); !(NTL::IsZero(tmp)); tmp/=2) res << (tmp%2);
    return res.str();
}

std::string zz_to_hex(const NTL::ZZ_p &num, size_t padding){
    std::ostringstream os;
    NTL::ZZ n = NTL::rep(num);
    std::vector<unsigned char> p(NumBytes(n));
    BytesFromZZ(p.data(), n, NumBytes(n));
    for (auto elem: p){
        std::ostringstream tmp;
        tmp << std::hex << (int) elem;
        if (tmp.str().size() == 1)
            os << "0";
        os << tmp.str();
    }
    while (os.str().size() < padding)
        os << "0";
    return os.str();
}

int swap(int d){
   int a;
   unsigned char *dst = (unsigned char *)&a;
   unsigned char *src = (unsigned char *)&d;

   dst[0] = src[3];
   dst[1] = src[2];
   dst[2] = src[1];
   dst[3] = src[0];

   return a;
}

int create_folders(){
    boost::system::error_code returnedError;

    boost::filesystem::create_directories( recon_settings.recon_tmp_folder, returnedError );

    if ( returnedError )
        return -1;  // did not successfully create directories
    else
        return 0;
}


}
