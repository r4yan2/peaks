#ifndef MESSAGE_H
#define MESSAGE_H
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include "myset.h"
#include <map>
#include <istream>
#include <sstream>
#include <common/utils.h>
#include "Bitset.h"
#include <sys/syslog.h>
#include <unordered_set>

namespace peaks {
namespace recon {

typedef Bitset bitset;

/** Possible message types send/received during recon */
namespace Msg_type{
enum Msg_type : int {
    ReconRequestPoly=0,
    ReconRequestFull=1,
    Elements=2,
    FullElements=3,
    SyncFail=4,
    Done=5,
    Flush=6,
    Error=7,
    DBRequest=8,
    DBReply=9,
    Peer_config=10,
    Config_mismatch=11,
    Config_ok=12
};
}

/** class which holds the to-be-sent/received serialized data.
 * Used to serialize and de-serialize data
 * when respectively sending and receiving
 * data from the other peer in the network.
 * When initialized with received content
 * read flag should be set so that the buffer
 * will not be used to write further data
 * TODO a better idea would be to differentiate
 * read buffer from write buffer.
 */
class Buffer{
    private:
        /** uchar vector act as byte vector */
        std::vector<unsigned char> buf;
        /** flag which indicate if buffer is read-only */
        bool read;
        /** iterator used to read from the buf vector */
        std::vector<unsigned char>::iterator it;
    public:
	    /** default constructor */
        Buffer();
        /** 
	     * buffer constructor with size specifier
         * @param size of the buffer
         */
        Buffer(int);

	    /**
	     * buffer constructor with given content
         * @param string which init buffer
         */
        Buffer(const std::string&);

	    /** access to the underliyng std::vector data */
        unsigned char* data();

        /** return size of the buffer */
        int size() const;

	    /** set the buffer to read only, so initialize the iterator
         * from this moment the buffer should be accessed only to read
	     * @WARNING the read-only logic is only conventional and not implemented yet!
	    */ 
        void set_read_only();

        /** clear buffer
         */
        void clear();

        std::vector<unsigned char> vector() const;
        std::string to_str() const;
        char* c_str() const;

        /** write an integer to the buffer.
         * Uses Big endian notation
         */
        void write_int(int);

        /** write a string to the buffer.
         * First write the length of the string
         * Then write the string itself.
         */
        void write_string(const std::string&);

        /** write a byte string to the buffer.
         * Like write_string
         */
        void write_bytes(const std::vector<unsigned char>&);

        /** write a set composed of ZZ_p elements.
         * First write the length of the zpset
         * Then proceed to write elements one by one
         * using the appropriate method
         */
        void write_zpset(const zpset&);

        /** write a bitstring.
         * First write the bitlength of the string
         * Then proceed to write the bitstring as a
         * common string, using its byte representation.
         */
        void write_bitset(const bitset&);

        /** write a ZZ_p type number to the buffer.
         * The byte representation of the number
         * is padded to a constant number, and 
         * the resulting byte string
         * is sent as a byte string
         */
        void write_zz_p(const NTL::ZZ_p&, int pad_to = 0);

        /** write an array of ZZ_p elements.
         * First write the length of the zpset
         * Then proceed to write elements one by one
         * using the appropriate method
         */
        void write_zz_array(const std::vector<NTL::ZZ_p>&);

        /** write the len of buf array.
         * This is the last write before sending
         * the buffer to the other peer.
         */
        void write_self_len();

        /** read an int from the buffer.
         * read an integer number from buf, using 
         * big endian notation.
         */
        int read_int();

        /** read a single byte from the buffer.
         * This single byte will determine 
         * the type of message which follow
         */
        uint8_t read_uint8();

        /** read a string from the buffer.
         * Read a char string from the buffer
         * by first examining the length (int)
         * and then by dumping the given number of
         * bytes into a proper string.
         */
        std::string read_string();

        /** read a set of ZZ_p from the buffer.
         * the set is read as an array and 
         * converted into a set.
         */
        zpset read_zpset();

        /** read a bistring from the buffer.
         * First the bitsize is read.
         * Then the bytes composing the 
         * bitstring are read like a common
         * string.
         */
        bitset read_bitset();

        /** read a ZZ_p number from the buffer.
         */
        NTL::ZZ_p read_zz_p();

        /** read an array of ZZ_p number from the buffer.
         */
        std::vector<NTL::ZZ_p> read_zz_array();

        /** read bytes from the buffer */
        std::vector<unsigned char> read_bytes(int size);

        /** Simple "push back" of a byte into
         * the buffer.
         */
        void push_back(unsigned char);

        /** Simple padding.
         * When some padding is needed
         * a zero content array is created
         * and put in append at the end
         * of the current one.
         */
        void padding(int padding_len);

        /** Append another buffer to the
         * end of this.
         */
        void append(const Buffer& other);
};

/** Abstract message struct.
 * All currently implemented message inherit
 * from this.
 */
struct Message{
    uint8_t type;
    Message(uint8_t _type):type(_type){}
};

/** Recon Request Poly type message.
 * This message is sent when trying to recover
 * keys by interpolation of a given node.
 */
struct ReconRequestPoly: Message{
    ReconRequestPoly():Message(Msg_type::ReconRequestPoly){}
    bitset prefix;
    int size;
    std::vector<NTL::ZZ_p> samples;
    void marshal(Buffer &buf);
    void unmarshal(Buffer &buf);
};

/** Recon Request Full type message.
 * When a ReconRequestPoly fails, this
 * type of message is sent insted to 
 * communicate all elements of a node.
 */
struct ReconRequestFull: Message{
    ReconRequestFull():Message(Msg_type::ReconRequestFull){}
    bitset prefix;
    zpset elements;
    void marshal(Buffer &buf);
    void unmarshal(Buffer &buf);
};

/** Elements type message.
 * When peer make a diff between local and remote
 * set of elements for a given node, send
 * results using this king of message.
 */
struct Elements: Message{
    Elements():Message(Msg_type::Elements){}
    zpset elements;
    void marshal(Buffer &buf);
    void unmarshal(Buffer &buf);
};

/** FullElements type message.
 * When a Recon Request Poly fails, this message is
 * sent from the client for the node which
 * RRP has failed.
 */
struct FullElements: Message{
    FullElements():Message(Msg_type::FullElements){}
    zpset elements;
    void marshal(Buffer &buf);
    void unmarshal(Buffer &buf);
};

/** SyncFail type message.
 * Used to indicate whereas a syncronization
 * step has failed 
 */
struct SyncFail: Message{
    SyncFail():Message(Msg_type::SyncFail){}
    void marshal(Buffer &buf);
    void unmarshal(Buffer &buf);
};

/** Done type message.
 * Used to signal that syncronization
 * is ended correctly
 */
struct Done: Message{
    Done():Message(Msg_type::Done){}
    void marshal(Buffer &buf);
    void unmarshal(Buffer &buf);
};

/** Flush type message.
 * Used by recon server to signal
 * client that has to send queued 
 * messages.
 */
struct Flush: Message{
    Flush():Message(Msg_type::Flush){}
    void marshal(Buffer &buf);
    void unmarshal(Buffer &buf);
};

/** Error type message.
 * Used to indicate that a critical
 * error was found during recon,
 * and operation will be aborted.
 */
struct Error: Message{
    Error():Message(Msg_type::Error){}
    std::string text;
    void marshal(Buffer &buf);
    void unmarshal(Buffer &buf);
};

/** DBRequest message.
 * Currently unused.
 */
struct DBRequest: Message{
    DBRequest():Message(Msg_type::DBRequest){}
    std::string text;
    void marshal(Buffer &buf);
    void unmarshal(Buffer &buf);
};

/** DBReply message.
 * Currently unused.
 */
struct DBReply: Message{
    DBReply():Message(Msg_type::DBReply){}
    std::string text;
    void marshal(Buffer &buf);
    void unmarshal(Buffer &buf);
};

/** Struct for sending peer data.
 *  this will be send via networking
 *  to the other peer for config
 *  syncronization before actual
 *  gossiping can occur
 */
struct Peer_config: Message{
    Peer_config():Message(Msg_type::Peer_config){}
    std::string version;
    int http_port; 
    int bq;
    int mbar;
    std::string filters;
    std::map<std::string, std::string> other;
    void marshal(Buffer &buf);
    void unmarshal(Buffer &buf);
};

/** Struct for sending a mismatch in config.
 * This is a custom message to send a 'failed'
 * message in case there's some config mismatch
 * and recon should not occur.
 */
struct Config_mismatch: Message{
    Config_mismatch():Message(Msg_type::Config_mismatch){}
    std::string failed = "failed";
    std::string reason;
    void marshal(Buffer &buf);
};

/** Struct for sending the config confirmation.
 * This is a custom message to send a 'ok'
 * command when the config is succesfully accepted
 */
struct Config_ok: Message{
    Config_ok():Message(Msg_type::Config_ok){}
    std::string passed = "passed";
    void marshal(Buffer &buf);
};

}
}

#endif
