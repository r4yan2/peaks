#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h> 
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <iostream>
#include <NTL/vector.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include "myset.h"
#include <map>
#include <istream>
#include <streambuf>
#include "exception.h"
#include "Message.h"
#include <algorithm>
#include <sys/syslog.h>


using namespace peaks::recon;
typedef Myset<NTL::ZZ_p> zset;
typedef std::pair<std::string, int> member;

namespace peaks{
namespace recon{

class Peer {
    public:
        std::string hostname;
        int port;
        int socket;
        Peer(const char*, int);
        Peer(const std::string &, int);
};

struct Bad_client : std::runtime_error{
    Bad_client():runtime_error(""){};
};

/**
 * Communication_status is a flag checked at each iteration
 * of the sync protocol to ensure the process is going
 * on without errors, or it's finished
 */
enum class Communication_status {NONE, ERROR, DONE};

/** 
 * Communication struct is needed to 
 * keep track of the messages between 
 * server and client.
 */
struct Communication{
    /** elements resulting from the current communication */
    zpset elements;
    /** flag to mark if queued messages has to be send */
    bool send;
    /** status of the current message exchange */
    Communication_status status;
    /** Messages generated from the current message exchange */
    std::vector<recon::Message*> messages;
    /** Default constructor for this struct, set send to false and communication status to None */
    Communication():send(false), status(Communication_status::NONE){}
};



class Connection {
    private:
        std::mutex& m; // I don't really like this
        Peer peer;
        int sockfd;

        /** helper method to activate keep-alive
         * on a given socket
         */
        bool toggle_keep_alive(int toggle, int idle, int interval, int count);

        /** helper method to set timeout on a given socket */
        void set_timeout();

        /** read only n bytes from network, and store into buf */
        bool read_n_bytes(void *buf, std::size_t n, int signal=MSG_WAITALL);

        /** read a sks-type Message */
        Message* read_message(bool &ok, bool async=false);

        /** perform the actual send */
        void send_peer(Buffer& buf);

    	/** send a message to the other peer */
        void send_message(Message*);

    	/** send a series of messages to the other peer */
        void send_bulk_messages(std::vector<Message*>);

	    /** send a message without header */
        void send_message_direct(Message*);

        /** direct read a string from the network */
        std::string read_string_direct();

        /** send a sks-type message */
        void write_message(Buffer &buffer, Message* m, bool wrap=true);

	    /** fail accordingly to the error passed */
        void early_fail(std::string);

        /** helper to check if the socket is still valid */
        bool check_socket_status();


    public:
        /**
         * constructor
         */
        Connection(std::mutex &, const std::string & _hostname, int _port, int _socket);
        Connection(std::mutex &, const char* _hostname, int _socket);
        Connection(std::mutex &, const char* _hostname, int _port, int _socket);
        Connection(std::mutex &, const std::string & _hostname, int _socket);
        /** Gracefully close the connection and free the used socket */
        ~Connection();

        /**
         * getter for peer
         */
        Peer get_peer();

        /**
         * Manage interaction with the client during recon
         */
        std::vector<NTL::ZZ_p> interact_with_client();

        /** handler of recon request poly messages
         * @param req request to handle
         * @return step from the handling
         */
        Communication request_poly_handler(ReconRequestPoly* req);

        /** handler of recon request full messages 
         * @param req request to handle
         * @return step from the handling
         */
        Communication request_full_handler(ReconRequestFull* req);


        /** 
         * recon as client with choosen peer
         */
        std::vector<NTL::ZZ_p> client_recon();

        /** exchange and validate config with peer */
        bool check_remote_config();

        /** implementation of linear interpolation
         * @param r_samples remote samples
         * @param r_size size of remote samples vector
         * @param l_samples local samples
         * @param l_size size of local samples vector
         * @param points default interpolation points
         * @return a pair of elements vectors which holds the respectively missing elements
         */
        static std::pair<std::vector<NTL::ZZ_p>,std::vector<NTL::ZZ_p>> solve(const std::vector<NTL::ZZ_p> &r_samples, const int r_size, const std::vector<NTL::ZZ_p> &l_samples, const int l_size, const std::vector<NTL::ZZ_p> &points);




};

/** singleton class used to manage the connection with the other peer.
 * Upon establishing a connection a tmpfd socket is used, and only when
 * all check are passed this became a permanent socket for the rest of the syncronization.
 * When the algorithm ends the socket is released
 */
class Connection_Manager{
    private:
        int listenfd;
        std::mutex mtx;
    public:

        /** default constructor */
        Connection_Manager();

        /** init connection as client 
         * with given peer peer */
        Connection init_peer(const member & peer);

        /** init server listener on the given port */
        void setup_listener(int portno);

        /** acceptor (this is only the accept part, 
         * has to be called in a loop to be effective 
         */
        Connection acceptor(std::vector<std::string> & addresses);

};

}
}
#endif
