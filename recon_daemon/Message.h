#ifndef MESSAGE_H
#define MESSAGE_H
#include <NTL/vector.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include <boost/dynamic_bitset.hpp>
#include "myset.h"
#include <map>
#include "logger.h"
#include "Recon_settings.h"

typedef boost::dynamic_bitset<unsigned char> bitset;
using namespace NTL;
typedef Myset<ZZ_p> zset;

namespace Msg_type{
enum Msg_type : int {
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
    Peer_config=10,
    Config_mismatch=11,
    Config_ok=12
};
}

class Buffer{
    private:
        std::vector<unsigned char> buf;
        bool read;
        std::vector<unsigned char>::iterator it;
    public:
        Buffer();
        Buffer(int);
        Buffer(std::string);
        unsigned char* data();
        int size();
        void set_read_only();
        std::vector<unsigned char> buffer();
        std::string to_str();
        void write_int(int);
        void write_string(std::string);
        void write_zset(zset);
        void write_bitset(bitset);
        void write_zz_p(ZZ_p);
        void write_zz_array(Vec<ZZ_p>);
        void write_self_len();
        int read_int(bool check_len=false);
        uint8_t read_uint8();
        std::string read_string();
        zset read_zset();
        bitset read_bitset();
        ZZ_p read_zz_p();
        Vec<ZZ_p> read_zz_array();
        std::vector<unsigned char> read_bytes(int size);
        void push_back(unsigned char);
        void append(Buffer);
        void padding(int padding_len);
};

typedef Buffer buftype;
typedef Buffer sbuftype;

struct Message{
    uint8_t type;
    Message(uint8_t _type):type(_type){}
};


struct ReconRequestPoly: Message{
    ReconRequestPoly():Message(Msg_type::ReconRequestPoly){}
    bitset prefix;
    int size;
    Vec<ZZ_p> samples;
    void marshal(buftype &buf);
    void unmarshal(sbuftype buf);
};


struct ReconRequestFull: Message{
    ReconRequestFull():Message(Msg_type::ReconRequestFull){}
    bitset prefix;
    zset samples;
    void marshal(buftype &buf);
    void unmarshal(sbuftype buf);
};

struct Elements: Message{
    Elements():Message(Msg_type::Elements){}
    zset samples;
    void marshal(buftype &buf);
    void unmarshal(sbuftype buf);
};

struct FullElements: Message{
    FullElements():Message(Msg_type::FullElements){}
    zset samples;
    void marshal(buftype &buf);
    void unmarshal(sbuftype buf);
};

struct SyncFail: Message{
    SyncFail():Message(Msg_type::SyncFail){}
    void marshal(buftype &buf);
    void unmarshal(sbuftype buf);
};

struct Done: Message{
    Done():Message(Msg_type::Done){}
    void marshal(buftype &buf);
    void unmarshal(sbuftype buf);
};

struct Flush: Message{
    Flush():Message(Msg_type::Flush){}
    void marshal(buftype &buf);
    void unmarshal(sbuftype buf);
};

struct ErrorType: Message{
    ErrorType():Message(Msg_type::ErrorType){}
    std::string text;
    void marshal(buftype &buf);
    void unmarshal(sbuftype buf);
};

struct DBRequest: Message{
    DBRequest():Message(Msg_type::DBRequest){}
    std::string text;
    void marshal(buftype &buf);
    void unmarshal(sbuftype buf);
};

struct DBReply: Message{
    DBReply():Message(Msg_type::DBReply){}
    std::string text;
    void marshal(buftype &buf);
    void unmarshal(sbuftype buf);
};

struct Peer_config: Message{
    Peer_config():Message(Msg_type::Peer_config){}
    std::string version;
    int http_port; 
    int bq;
    int mbar;
    std::string filters;
    std::map<std::string, std::string> other;
    void marshal(buftype &buf);
    void unmarshal(sbuftype buf);
};

struct Config_mismatch: Message{
    Config_mismatch():Message(Msg_type::Config_mismatch){}
    std::string failed = "failed";
    std::string reason;
    void marshal(buftype &buf);
};

struct Config_ok: Message{
    Config_ok():Message(Msg_type::Config_ok){}
    std::string passed = "passed";
    void marshal(buftype &buf);
};

#endif
