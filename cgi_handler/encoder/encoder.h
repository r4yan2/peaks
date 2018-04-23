#ifndef ENCODER_H
#define ENCODER_H

#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>
#include <array>
#include <string>

namespace text_encoder
{

using std::vector;
using std::array;
using std::istream;
using std::string;
using std::stringstream;
using std::back_inserter;

/** 
 * Virtual encoder/decoder class
 */
class base_encoder
{
public:
    virtual bool encode(const vector<char>& in, vector<char>& out) = 0;
    virtual bool decode(const vector<char>& in, vector<char>& out) = 0;
};

/**
 * Base64 encoder/decoder
 */
class base64_encoder : public base_encoder
{
public:
    virtual bool encode(const vector<char>& in, vector<char>& out);
    virtual bool decode(const vector<char>& in, vector<char>& out) 
    { 
        return false;
    }

private:
    static const std::string b64map;

    inline void block_convert(const array<char,3>& in, array<char, 4>& out)
    {
        const uint8_t *i = reinterpret_cast<const uint8_t*>(&in[0]);
        out[0] = i[0] >> 2;
        out[1] = ((i[0]&0x03) << 4) | ((i[1]&0xf0) >> 4);
        out[2] = ((i[1]&0x0f) << 2) | ((i[2]&0xc0) >> 6);
        out[3] = i[2] & 0x3f;
    }
};

/**
 * Radix64 encoder/decoder
 */
class radix64 : public base_encoder
{
public:
    radix64() : headers_size(0) {}

    radix64(const vector<string>& headers) : headers(headers), headers_size(0) 
    {

        for(const string& s : headers)
            headers_size += s.length();
    }

    void add_headers(const string& header) 
    {
        headers.push_back(header);
        headers_size += header.length();
    }

    virtual bool encode(std::istream& in, std::string& out);

    virtual bool encode(const vector<char>& in, vector<char>& out);
    virtual bool decode(const vector<char>& in, vector<char>& out)
    { 
        return false;
    }
private:
    base64_encoder b64;
    vector<string> headers;
    vector<string>::size_type headers_size;

    // Source: http://tools.ietf.org/html/rfc4880#section-6.1 
    #define CRC24_INIT 0xB704CEL
    #define CRC24_POLY 0x1864CFBL

    typedef long crc24;
    crc24 crc_octets(char *octets, size_t len)
    {
        register crc24 crc = CRC24_INIT;
        register int i;
        while (len--)
        {
            crc ^= (*octets++) << 16;
            for (i = 0; i < 8; i++)
            {
                crc <<= 1;
                if (crc & 0x1000000)
                    crc ^= CRC24_POLY;
            }
        }

        return crc & 0xFFFFFFL;
    }
};

}; // end namespace text_encoder

#endif
