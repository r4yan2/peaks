#include "Message.h"

Buffer::Buffer(){}
Buffer::Buffer(int size){
    buf.resize(size);
    bzero(buf.data(), buf.size());
}

Buffer::Buffer(std::string initializer){
    buf = std::vector<unsigned char>(initializer.begin(), initializer.end());
    it = buf.begin();
}

void Buffer::set_read_only(){
    read = true;
    it = buf.begin();
}

int Buffer::size(){
    return buf.size();
}

unsigned char* Buffer::data(){
    return buf.data();
}

std::vector<unsigned char> Buffer::vector(){
    return buf;
}

void Buffer::push_back(unsigned char elem){
    buf.push_back(elem);
}

std::string Buffer::to_str(){
    return std::string(buf.begin(), buf.end());
}

void Buffer::write_self_len(){
    int size = buf.size();
    unsigned char *dst = (unsigned char *)&size;
    for (int i=3; i>=0; i--)
        buf.push_back(dst[i]);
    std::rotate(buf.rbegin(), buf.rbegin()+4, buf.rend());
}

void Buffer::write_int(int to_write){
    unsigned char *ptr = (unsigned char *)&to_write;
    for (int i=3; i>=0; i--) buf.push_back(ptr[i]);
}

void Buffer::append(Buffer other){
    std::vector<unsigned char> v = other.vector();
    buf.insert(buf.end(), v.begin(), v.end());
}

void Buffer::write_zset(zset to_write){
    write_zz_array(to_write.elements());
}

void Buffer::write_bitset(bitset to_write){
    write_int(to_write.size());
    write_int(to_write.num_blocks());

    int sz = buf.size();
    auto ii = std::back_inserter(buf);
    to_block_range(to_write, ii);
    for (it=buf.begin()+sz; it<buf.end(); it++){
        *it = (*it & 0xF0) >> 4 | (*it & 0x0F) << 4;
        *it = (*it & 0xCC) >> 2 | (*it & 0x33) << 2;
        *it = (*it & 0xAA) >> 1 | (*it & 0x55) << 1;
    }
  /*  
    bitset tmp;
    for (it=; i<8; i++){
        
    }
    if (to_write.size() > 0){
        unsigned long tmp = to_write.to_ulong();
        unsigned char *p = (unsigned char *)&tmp;
    //std::cout << sizeof(p[0]) << std::endl;
        buf.push_back(p[0]<<6);
    }
    */
    
}

void Buffer::write_string(std::string to_write){
    write_int(to_write.size());
    buf.insert(buf.end(),to_write.begin(),to_write.end());
}

void Buffer::write_zz_array(std::vector<NTL::ZZ_p> to_write){
    write_int(to_write.size());
    for (int i=0; i<to_write.size(); i++) 
            write_zz_p(to_write[i]);
    g_logger.log(Logger_level::DEBUG, "Wrote NTL::ZZ_p array to buffer succesfully");
}

void Buffer::write_zz_p(NTL::ZZ_p to_write, int pad_to){
    //reinit of the module is needed, otherwise ntl will
    //complain
    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(Recon_settings::P_SKS_STRING.c_str()));

    NTL::ZZ z = rep(to_write);
    int num_bytes = NumBytes(z);
    std::vector<unsigned char> buf_z(num_bytes);
    BytesFromZZ(buf_z.data(), z, num_bytes);
    buf.insert(buf.end(), buf_z.begin(), buf_z.end());
    if (num_bytes < Recon_settings::sks_zp_bytes){
        padding(pad_to - num_bytes);
    }
}

uint8_t Buffer::read_uint8(){
    uint8_t res = (uint8_t) *it;
    it++;
    return res;
}

// Read int from data chunk
int Buffer::read_int(bool check_len){
    int res;
    unsigned char *dst = (unsigned char *)&res;

    for (int i=3; i>=0; i--, it++) dst[i] = *it;
    if (check_len && (res > Recon_settings::max_read_len)) g_logger.log(Logger_level::WARNING, "Oversized message!");
    return res;
}

// Reads bitset from data chunk
bitset Buffer::read_bitset() {
    int bs_size = read_int();
    int bytes = read_int();
    bitset bs;
    if (bytes != 0){
        bs.append(it, it+bytes);
        it+=bytes;
    }
    bs.resize(bs_size);
    std::ostringstream os;
    os << bs;
    g_logger.log(Logger_level::DEBUG, os.str());
    return bs;
}

std::vector<NTL::ZZ_p> Buffer::read_zz_array(){
    //reinit of the module is needed, otherwise ntl will
    //complain
    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(Recon_settings::P_SKS_STRING.c_str()));
    int array_size = read_int();
    std::vector<NTL::ZZ_p> array(array_size);
    /*
    g_logger.log(Logger_level::DEBUG, "zz array size set accordingly");
    std::ostringstream os;
    os << "resulting zz array: [";
    */
    for (int i=0; i<array_size; i++){
        std::vector<unsigned char> zbytes = read_bytes(Recon_settings::sks_zp_bytes);
        NTL::ZZ_p dst;
        NTL::ZZ_p a(256);
        for (int i=0; i<zbytes.size(); i++){
            NTL::ZZ_p x;
            power(x, a, i);
            dst += x * (uint8_t)zbytes[i];
        }
        array[i]=dst;
        //os << dst;
        //os << " ";
    }
    //os << "]" << std::endl;
    //g_logger.log(Logger_level::DEBUG, os.str());
    return array;
}

zset Buffer::read_zset(){
    std::vector<NTL::ZZ_p> array = read_zz_array();
    zset result(array);
    return result;
}

std::string Buffer::read_string(){
    int size = read_int();
    if (size == 0) return "";
    std::string result(it, it+size);
    it+=size;
    return result;
}

std::vector<unsigned char> Buffer::read_bytes(int size){
    std::vector<unsigned char> res(it, it+size);
    it+=size;
    return res;
}

void Buffer::padding(int padding_len){
    std::vector<unsigned char> pad(padding_len);
    bzero(pad.data(), pad.size());
    buf.insert(buf.end(), pad.begin(), pad.end());
}
