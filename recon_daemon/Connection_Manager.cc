#include "Connection_Manager.h"
using namespace Utils;

Connection_Manager::Connection_Manager(){}
Connection_Manager::~Connection_Manager(){}

void Connection_Manager::init(peertype peer){
    int portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    std::string hostname;

    hostname = peer.first;
    portno = peer.second;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        syslog(LOG_INFO, "ERROR opening socket");
    server = gethostbyname(hostname.c_str());
    if (server == NULL) {
        syslog(LOG_INFO, "ERROR, no such host");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
    (char *)&serv_addr.sin_addr.s_addr,
    server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        syslog(LOG_INFO, "ERROR connecting");
}


Peer_config Connection_Manager::get_remote_config(Peer_config peer_config){

    Peer_config remote_config;
    send(sockfd, &peer_config, sizeof(peer_config), 0);
    recv(sockfd, &remote_config, sizeof(Peer_config), 0);
    return remote_config;
}

bool Connection_Manager::read_n_bytes(void *buf, std::size_t n) {
    std::size_t offset = 0;
    char *cbuf = reinterpret_cast<char*>(buf);
    while (true) {
        ssize_t ret = recv(sockfd, cbuf + offset, n - offset, MSG_WAITALL);
        if (ret < 0 && errno != EINTR) {
            // IOException
            throw std::invalid_argument(strerror(errno));
        } else if (ret == 0) {
            // No data available anymore
            if (offset == 0) return false;
            else{
                //Protocol Exception
                throw std::underflow_error("Unexpected end of stream");
            }
        } else if (offset + ret == n) {
            // All n bytes read
            return true;
        } else {
            offset += ret;
        }
    }
}

Message::Message(){
    sks_zp_bytes = NumBytes(ZZ_p::modulus());
}

template<typename CharT, typename TraitsT = std::char_traits<CharT> >
class vectorwrapbuf : public std::basic_streambuf<CharT, TraitsT> {
public:
    vectorwrapbuf(std::vector<CharT> &vec) {
        setg(vec.data(), vec.data(), vec.data() + vec.size());
    }
};


// Reads message from network
Message Connection_Manager::read_message() {
   std::uint32_t size;
   if (read_n_bytes(&size, sizeof(size))) {
       size = Utils::swap(size);
       if (size > max_read_len) syslog(LOG_INFO, "Oversized message!");
       buftype buf(size);
       if (read_n_bytes(buf.data(), size)) {
           vectorwrapbuf<unsigned char> data(buf);
           sbuftype ibuf(&data);
           Message msg;
           msg.type = uint8_t(Utils::pop_front(buf));
           msg.unmarshal(ibuf);
           return msg;
       } else {
           //Protocol Exception
           throw std::underflow_error("Unexpected end of stream");
       }
   } else {
       // connection was closed
       throw std::underflow_error("Unexpected end of stream");
   }
}

// Read int from data chunk
int Message::read_int(sbuftype &buf, bool check_len){
    int res;
    unsigned char *dst = (unsigned char *)&res;

    for (int i=3; i>=0; i--) buf.read(&dst[i], 1);
    if (check_len && (res > max_read_len)) syslog(LOG_INFO, "Oversized message!");
    return res;
}

// Reads bitset from data chunk
bitset Message::read_bitset(sbuftype &buf) {
    int bs_size;
    bs_size = read_int(buf);
    int bytes;
    bytes = read_int(buf);
    bitset bs;
    if (bytes != 0){
        std::vector<unsigned char> tmp(bytes);
        buf.read((unsigned char *) &tmp[0], bytes);
        bs.append(tmp.begin(), tmp.end());
    }
    return bs;
}

Vec<ZZ_p> Message::read_zz_array(sbuftype &buf){
    int array_size;
    array_size = read_int(buf);
    Vec<ZZ_p> array;
    array.SetLength(array_size);
    for (int i=0; i<array_size; i++){
        ZZ src;
        ZZ_p dst;
        std::vector<unsigned char> tmp(sks_zp_bytes);
        buf.read((unsigned char *) &tmp[0], sks_zp_bytes);
        ZZFromBytes(src, tmp.data(), sks_zp_bytes);
        conv(src, dst);
        array[i] = dst;
    }
    return array;
}

zset Message::read_zz_set(sbuftype &buf){
    Vec<ZZ_p> array = read_zz_array(buf);
    zset result(array);
    return result;
}

std::string Message::read_string(sbuftype &buf){
    int size;
    size = read_int(buf);
    if (size == 0) return "";
    std::vector<unsigned char> tmp(size);
    buf.read(&tmp[0], size);
    std::string result(tmp.begin(), tmp.end());
    return result;

}

void Message::unmarshal(sbuftype &buf){

    switch (type){
        case Msg_type::ReconRequestPoly: {
                    data = new ReconRequestPoly;
                    ((ReconRequestPoly *) data)->prefix = read_bitset(buf);
                    ((ReconRequestPoly *) data)->size = read_int(buf);
                    ((ReconRequestPoly *) data)->samples = read_zz_array(buf);
                    break;
                }
        case Msg_type::ReconRequestFull: {
                    data = new ReconRequestFull;
                    ((ReconRequestFull *) data)->prefix = read_bitset(buf);
                    ((ReconRequestFull *) data)->samples = read_zz_set(buf);
                    break;
                }
        case Msg_type::Elements: {
                    data = new Elements;
                    ((Elements *) data)->samples = read_zz_set(buf);
                    break;
                }
        case Msg_type::FullElements: {
                    data = new FullElements;
                    ((FullElements *) data)->samples = read_zz_set(buf);
                    break;
                }
        case Msg_type::SyncFail: {
                    data = new SyncFail;
                    break;
                }
        case Msg_type::Done: {
                    data = new Done;
                    break;
                }
        case Msg_type::Flush: {
                    data = new Flush;
                    break;
                }
        case Msg_type::ErrorType: {
                    data = new ErrorType;
                    ((ErrorType *) data)->text = read_string(buf);
                    break;
                }
        case Msg_type::DBRequest: {
                    data = new DBRequest;
                    ((DBRequest *) data)->text = read_string(buf);
                    break;
                }
        case Msg_type::DBReply: {
                    data = new DBReply;
                    ((DBReply *) data)->text = read_string(buf);
                    break;
                }
        case Msg_type::Peer_config: {
                     data = new Peer_config;
                     std::string key;
                     std::uint32_t val;
                     std::string value;
                     std::uint32_t a = read_int(buf, true);
                     for (uint32_t i=0; i<a; i++){
                     key = read_string(buf);
                     if ((key == "http port") ||
                        (key == "bitquantum") ||
                        (key == "mbar")) {
                        val = read_int(buf, true);
                        if (val != 4) syslog(LOG_INFO, "Invalid len size!");
                        val = read_int(buf);
                        }
                     else value = read_string(buf);
                     if (key == "version") ((Peer_config *) data)->version = value;
                     else if (key == "http port") ((Peer_config *) data)->http_port = val;
                     else if (key == "bitquantum") ((Peer_config *) data)->bq = val;
                     else if (key == "mbar") ((Peer_config *) data)->mbar = val;
                     else if (key == "filters") ((Peer_config *) data)->filters = value;
                     else ((Peer_config *) data)->other[key] = value;
                               }
                     }
                     
        default: syslog(LOG_INFO, "Cannot understand message type during recon!");
    }
}

void Message::marshal(buftype buf){
    switch(type){
        case Msg_type::ReconRequestPoly:
            {
                write_bitset(buf, ((ReconRequestPoly *)data)->prefix);
                write_int(buf, ((ReconRequestPoly *)data)->size);
                write_zz_array(buf, ((ReconRequestPoly *)data)->samples);
                break;
            }
        case Msg_type::ReconRequestFull:
            {
                write_bitset(buf, ((ReconRequestFull *)data)->prefix);
                write_zset(buf, ((ReconRequestFull *)data)->samples);
                break;
            }
        case Msg_type::Elements:
            {
                write_zset(buf, ((Elements *)data)->samples);
                break;
            }
        case Msg_type::FullElements:
            {
                write_zset(buf, ((FullElements *)data)->samples);
                break;
            }
        case Msg_type::SyncFail:
            break;
        case Msg_type::Done:
            break;
        case Msg_type::Flush:
            break;
        case Msg_type::ErrorType:
            {
                write_string(buf, ((ErrorType *)data)->text);
                break;
            }
        case Msg_type::DBRequest:
            {
                write_string(buf, ((DBRequest *)data)->text);
                break;
            }
        case Msg_type::DBReply:
            {
                write_string(buf, ((DBReply *)data)->text);
                break;
            }
        case Msg_type::Peer_config:
            {
                write_int(buf, 5 + ((Peer_config *)data)->other.size());
                write_string(buf, "version");
                write_string(buf, ((Peer_config *)data)->version);
                write_string(buf, "http port");
                write_int(buf, 4);
                write_int(buf, ((Peer_config *)data)->http_port);
                write_string(buf, "bitquantum");
                write_int(buf, 4);
                write_int(buf, ((Peer_config *)data)->bq);
                write_string(buf, "mbar");
                write_int(buf, 4);
                write_int(buf, ((Peer_config *)data)->mbar);
                write_string(buf, "filters");
                write_string(buf, ((Peer_config *)data)->filters);
                    if (not (((Peer_config *)data)->other.empty())){
                        for (auto kv: ((Peer_config *)data)->other){
                            write_string(buf, kv.first);
                            write_string(buf, kv.second);
                        }
                    }
                break;
            }
    }
}


void Connection_Manager::write_message(Message m){
    buftype buffer;
    buffer.push_back((char)m.type);
    m.marshal(buffer);
    int size = buffer.size();
    unsigned char *dst = (unsigned char *)&size;
    for (int i=3; i>=0; i--)
        buffer.push_back(dst[i]);
    std::rotate(buffer.rbegin(), buffer.rbegin()+4, buffer.rend());
    int err = write(sockfd, buffer.data(), buffer.size());
    if (err < 0)
        throw send_message_exception(); 
}

void Connection_Manager::send_items(zset response){
}

void Message::write_int(buftype buf, int to_write){
    unsigned char *ptr = (unsigned char *)&to_write;
    for (int i=3; i>=0; i--) buf.push_back(ptr[i]);
}

void Message::write_zset(buftype buf, zset to_write){
    write_zz_array(buf, to_write.elements());
}
void Message::write_bitset(buftype buf, bitset to_write){
    write_int(buf, to_write.size());
    write_int(buf, to_write.num_blocks());
    auto ii = std::back_inserter(buf);
    to_block_range(to_write, ii);
}
void Message::write_string(buftype buf, std::string to_write){
    write_int(buf, to_write.size());
    buf.insert(buf.end(),to_write.begin(),to_write.end());
}
void Message::write_zz_array(buftype buf, Vec<ZZ_p> to_write){
    write_int(buf, to_write.length());
    for (int i=0; i<to_write.length(); i++) 
            write_zz_p(buf, to_write[i]);
}
void Message::write_zz_p(buftype buf, ZZ_p to_write){
    ZZ z = rep(to_write);
    int num_bytes = NumBytes(z);
    buftype buf_z(num_bytes);
    BytesFromZZ(buf_z.data(), z, num_bytes);
    buf.insert(buf.end(), buf_z.begin(), buf_z.end());
    if (num_bytes < sks_zp_bytes){
        buftype padding(sks_zp_bytes - num_bytes);
        bzero(buf.data(), sizeof(buf));
        buf.insert(buf.end(), padding.begin(), padding.end());
    }
}

