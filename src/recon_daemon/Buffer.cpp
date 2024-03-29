#include "Message.h"
#include <common/utils.h>

using namespace peaks::common;
namespace peaks{
namespace recon{

Buffer::Buffer(){}
Buffer::Buffer(int size){
    buf.resize(size);
    bzero(buf.data(), buf.size());
}

Buffer::Buffer(const std::string &initializer){
    buf = std::vector<byte_t>(initializer.begin(), initializer.end());
    it = buf.begin();
}

Buffer::Buffer(std::shared_ptr<std::istream> stream){
    buf = std::vector<byte_t>(std::istreambuf_iterator<char>(*stream), {});
    it = buf.begin();
}

void Buffer::set_read_only(){
    read = true;
    it = buf.begin();
}

void Buffer::clear(){
  buf.clear();
}

int Buffer::size() const{
    return buf.size();
}

byte_t* Buffer::data(){
    return buf.data();
}

std::vector<byte_t> Buffer::vector() const{
    return buf;
}

void Buffer::push_back(byte_t elem){
    buf.push_back(elem);
}

std::string Buffer::to_str() const{
    return std::string(buf.begin(), buf.end());
}

char* Buffer::c_str() const{
    return (char*) buf.data();
}

void Buffer::write_self_len(){
    int size = buf.size();
    byte_t *dst = (byte_t *)&size;
    for (int i=3; i>=0; i--)
        buf.push_back(dst[i]);
    std::rotate(buf.rbegin(), buf.rbegin()+4, buf.rend());
}

void Buffer::write_int(int to_write){
    byte_t *ptr = (byte_t *)&to_write;
    for (int i=3; i>=0; i--) buf.push_back(ptr[i]);
}

void Buffer::append(const Buffer &other){
    std::vector<byte_t> v = other.vector();
    buf.insert(buf.end(), v.begin(), v.end());
}

void Buffer::write_zpset(const zpset &to_write){
    write_zz_array(to_write.elements());
}

void Buffer::write_bitset(const bitset &to_write){
    write_int(to_write.size());
    write_bytes(to_write.rep());
}

void Buffer::write_string(const std::string &to_write){
    write_int(to_write.size());
    buf.insert(buf.end(),to_write.begin(),to_write.end());
}

void Buffer::write_bytes(const std::vector<byte_t> &to_write){
    write_int(to_write.size());
    buf.insert(buf.end(),to_write.begin(),to_write.end());
}

void Buffer::write_zz_array(const std::vector<NTL::ZZ_p> &to_write){
    write_int(to_write.size());
    for (size_t i=0; i<to_write.size(); i++) 
        write_zz_p(to_write[i]);
}

void Buffer::write_zz_p(const NTL::ZZ_p &to_write, int pad_to){
    //reinit of the module is needed, otherwise ntl will
    //complain
    //NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(msg_settings.P_SKS_STRING.c_str()));
    if (pad_to == 0)
        pad_to = NumBytes(to_write.modulus());

    NTL::ZZ z = rep(to_write);
    int num_bytes = NumBytes(z);
    std::vector<byte_t> buf_z(num_bytes);
    BytesFromZZ(buf_z.data(), z, num_bytes);
    buf.insert(buf.end(), buf_z.begin(), buf_z.end());
    if (num_bytes < pad_to){
        padding(pad_to - num_bytes);
    }
}

uint8_t Buffer::read_uint8(){
    uint8_t res = (uint8_t) *it;
    it++;
    return res;
}

// Read int from data chunk
int Buffer::read_int(){
    unsigned int res;
    byte_t *dst = (byte_t *)&res;

    for (int i=3; i>=0; i--, it++) dst[i] = *it;
    return res;
}

// Reads bitset from data chunk
bitset Buffer::read_bitset() {
    int bs_size = read_int();
    int n_bytes = read_int();
    bitset bs(read_bytes(n_bytes));
    bs.resize(bs_size);
    return bs;
}

std::vector<NTL::ZZ_p> Buffer::read_zz_array(){
    //reinit of the module is needed, otherwise ntl will
    //complain
    //NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(msg_settings.P_SKS_STRING.c_str()));
    int array_size = read_int();
    std::vector<NTL::ZZ_p> array(array_size);
    for (int i=0; i<array_size; i++){
        std::vector<byte_t> zbytes = read_bytes(NumBytes(NTL::ZZ_p::modulus()));
        array[i] = Utils::bytes_to_zz(zbytes);
    }
    return array;
}

zpset Buffer::read_zpset(){
    std::vector<NTL::ZZ_p> array = read_zz_array();
    zpset result(array);
    return result;
}

std::string Buffer::read_string(){
    int size = read_int();
    if (size == 0) return "";
    std::string result(it, it+size);
    it+=size;
    return result;
}

std::vector<byte_t> Buffer::read_bytes(int size){
    std::vector<byte_t> res(it, it+size);
    it+=size;
    return res;
}

void Buffer::padding(int padding_len){
    std::vector<byte_t> pad(padding_len);
    bzero(pad.data(), pad.size());
    buf.insert(buf.end(), pad.begin(), pad.end());
}

}
}
