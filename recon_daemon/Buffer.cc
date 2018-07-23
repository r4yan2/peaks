#include "Message.h"

Buffer::Buffer(){}
Buffer::Buffer(int size){
    buf.resize(size);
    bzero(buf.data(), sizeof(buf));
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

std::vector<unsigned char> Buffer::buffer(){
    return buf;
}

void Buffer::push_back(unsigned char elem){
    buf.push_back(elem);
}

void Buffer::append(Buffer tail){
    buf.insert(buf.end(), tail.buffer().begin(), tail.buffer().end());
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

void Buffer::write_zset(zset to_write){
    write_zz_array(to_write.elements());
}

void Buffer::write_bitset(bitset to_write){
    write_int(to_write.size());
    write_int(to_write.num_blocks());
    auto ii = std::back_inserter(buf);
    to_block_range(to_write, ii);
}

void Buffer::write_string(std::string to_write){
    write_int(to_write.size());
    buf.insert(buf.end(),to_write.begin(),to_write.end());
}

void Buffer::write_zz_array(std::vector<ZZ_p> to_write){
    write_int(to_write.size());
    for (int i=0; i<to_write.size(); i++) 
            write_zz_p(to_write[i]);
}

void Buffer::write_zz_p(ZZ_p to_write){
    ZZ z = rep(to_write);
    int num_bytes = NumBytes(z);
    std::vector<unsigned char> buf_z(num_bytes);
    BytesFromZZ(buf_z.data(), z, num_bytes);
    buf.insert(buf.end(), buf_z.begin(), buf_z.end());
    if (num_bytes < Recon_settings::sks_zp_bytes){
        padding(Recon_settings::sks_zp_bytes - num_bytes);
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
    return bs;
}

std::vector<ZZ_p> Buffer::read_zz_array(){
    int array_size = read_int();
    g_logger.log(Logger_level::DEBUG, "zz array size: " + std::to_string(array_size));
    std::vector<ZZ_p> array(array_size);
    g_logger.log(Logger_level::DEBUG, "zz array size set accordingly");
    for (int i=0; i<array_size; i++){
        ZZ src;
        ZZFromBytes(src, &(*it), Recon_settings::sks_zp_bytes);
        g_logger.log(Logger_level::DEBUG, "zz read");
        it+=Recon_settings::sks_zp_bytes;
        ZZ_p dst = conv<ZZ_p>(src);
        array[i] = dst;
    }

    return array;
}

zset Buffer::read_zset(){
    std::vector<ZZ_p> array = read_zz_array();
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
    buftype padding(padding_len);
    append(padding);
}
