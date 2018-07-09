#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <string>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <iostream>
#include "Utils.h"
#include <NTL/vector.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include "myset.h"
#include <map>
#include <istream>
#include <streambuf>
#include "exception.h"

typedef std::pair<std::string, int> peertype;
using namespace NTL;
typedef boost::dynamic_bitset<unsigned char> bitset;
typedef std::vector<unsigned char> buftype;
typedef std::basic_istream<unsigned char> sbuftype;
typedef Myset<ZZ_p> zset;

const static int max_read_len = 1 << 24;
const static int max_recover_size = 15000;

struct Peer_config{
    std::string version;
    int http_port; 
    int bq;
    int mbar;
    std::string filters;
    std::map<std::string, std::string> other;
};

namespace Msg_type{
enum Msg_type : uint8_t {
    ReconRequestPoly=0,
    ReconRequestFull=1,
    Elements=2,
    FullElements=3,
    SyncFail=4,
    Done=5,
    Flush=6,
    ErrorType=7,
    DBRequest=8,
    DBReply=9,
    Peer_config=10
};
}

struct ReconRequestPoly{
    bitset prefix;
    int size;
    Vec<ZZ_p> samples;
};


struct ReconRequestFull{
    bitset prefix;
    zset samples;
};

struct Elements{
    zset samples;
};

struct FullElements{
    zset samples;
};

struct SyncFail{
};

struct Done{
};

struct Flush{
};

struct ErrorType{
    std::string text;
};

struct DBRequest{
    std::string text;
};

struct DBReply{
    std::string text;
};

class Message{
    private:
        int sks_zp_bytes;
    public:
        uint8_t type;
        void* data;

        Message();
        void unmarshal(sbuftype &buf);
        void marshal(buftype buf);
        zset read_zz_set(sbuftype &buf);
        std::string read_string(sbuftype &buf);
        bitset read_bitset(sbuftype &buf);
        int read_int(sbuftype &buf, bool check_len=false);
        Vec<ZZ_p> read_zz_array(sbuftype &buf);
        void write_int(buftype buf, int to_write);/**< write integer into buffer */
        void write_zset(buftype buf, zset to_write);/**< write set of zz_p into buffer  */
        void write_bitset(buftype buf, bitset to_write);/**< write bitstring to buffer */
        void write_string(buftype buf, std::string to_write);/**< write string to buffer */
        void write_zz_array(buftype buf, Vec<ZZ_p> to_write);/**< write NTL Vec of ZZ_p to buffer */
        void write_zz_p(buftype buf, ZZ_p to_write);/**< write NTL ZZ_p into buffer */
};

class Connection_Manager{
    private:
        int sockfd;
    public:

        Connection_Manager();
        void init(peertype peer);
        Peer_config get_remote_config(Peer_config peer_config);
        ~Connection_Manager();
        bool read_n_bytes(void *buf, std::size_t n);
        Message read_message();
        bitset read_bitset();

        void write_message(Message m);/**< Send message to peer */
        void send_items(zset response);/**< Send zset to peer */
};

#endif
