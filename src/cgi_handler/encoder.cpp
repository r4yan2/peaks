#include <Misc/radix64.h>
#include "encoder.h"

namespace peaks {
namespace pks{
namespace text_encoder{

const std::string base64_encoder::b64map =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

bool base64_encoder::encode(const vector<char>& in, vector<char>& out)
{
    string tmp = OpenPGP::ascii2radix64(string(in.begin(), in.end()));
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(out));
    return true;
    /*
    array<char,3> tp1;
    array<char,4> tp2;

    out.clear();
    out.reserve(((in.size()+2)/3)*4 + 1);

    vector<char>::size_type i = 0;
    while(i+3 < in.size())
    {
        for(int j=0;j<3;j++)
            tp1[j] = in[i+j];
        block_convert(tp1, tp2);
        for(int j=0;j<4;j++)
            out.push_back(b64map[tp2[j]]);
        i+=3;
    }

    for(int j=0;j<3;j++)
        tp1[j] = (i+j) < in.size() ? in[i+j] : 0;

    block_convert(tp1, tp2);
    if(i+2 == in.size()) tp2[3] = 0x7f;
    if(i+1 == in.size()) tp2[2] = tp2[3] = 0x7f;

    for(int j=0;j<4;j++)
        if(tp2[j] == 0x7f)
            out.push_back('=');
        else
            out.push_back(b64map[tp2[j]]);
    return true;*/
}

bool radix64::encode(std::istream& in, std::string& out)
{
    vector<char> data;
    vector<char> vout;

    if(!in.good())
        return false;

    in.seekg(0, in.end);
    istream::streampos size = in.tellg();
    in.seekg(0, in.beg);

    if(size == 0)
        return false;

    data.resize((size_t)size);
    in.read(&data[0], size);

    if(!this->encode(data, vout))
        return false;

    out = string(vout.begin(), vout.end());
    return true;

}

bool radix64::encode(const vector<char>& in, vector<char>& out)
{
    static const std::string hdr = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n";
    static const std::string btm = "-----END PGP PUBLIC KEY BLOCK-----";

    vector<char> tmp;
    b64.encode(in, tmp);

    out.clear();
    size_t b64_size = ((in.size()+2)/3)*4;
    size_t estimated_size =
          hdr.length()
        + headers_size
        + headers.size()        // \n for each header
        + 1                     // \n before base64
        + b64_size              // base64
        + b64_size/72           // newlines
        + ((b64_size%72) != 0)  // len(lastline) < 64 ? +1
        + 6                     // =2345\n (checksum)
        + btm.length()          // bottom length
    ;

    out.reserve(estimated_size);
    copy(hdr.begin(), hdr.end(), back_inserter(out));

    for(const string& s : headers)
    {
        copy(s.begin(), s.end(), back_inserter(out));
        out.push_back('\n');
    }

    out.push_back('\n');
    int n = 0;
    for(char i : tmp)
    {
        if(n && !(n % 72))
        {
            out.push_back('\n');
            n = 0;
        }
        out.push_back(i);
        n++;
    }
    if(n != 1) // n == 1 <-> just inserted \n
        out.push_back('\n');

    // CHECKSUM
    crc24 crc = crc_octets((char *)&in[0], in.size());

    tmp.resize(3);
    tmp[0] = (crc >> 16) & 0xff;
    tmp[1] = (crc >> 8) & 0xff;
    tmp[2] = crc & 0xff;

    vector<char> tmp2;
    b64.encode(tmp, tmp2);

    out.push_back('=');
    for(char i : tmp2)
        out.push_back(i);
    out.push_back('\n');
    // END CHECKSUM

    copy(btm.begin(), btm.end(), std::back_inserter(out));
    return true;
};

}
}
} // end namespace text_encoder
