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
#include "Utils.h"
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
#include "Recon_settings.h"
#include <sys/syslog.h>

typedef std::pair<std::string, int> peertype;
typedef Myset<NTL::ZZ_p> zset;

struct Bad_client : std::runtime_error{
    Bad_client():runtime_error(""){};
};

/** singleton class used to manage the connection with the other peer.
 * Upon establishing a connection a tmpfd socket is used, and only when
 * all check are passed this became a permanent socket for the rest of the syncronization.
 * When the algorithm ends the socket is released
 */
class Connection_Manager{
    private:
        int sockfd;
        int tmpfd;
        int listenfd;
        Connection_config settings;
    public:

        /** default constructor */
        Connection_Manager(const Connection_config &conn_settings);

        /** init connection as client 
         * with given peer peer */
        int init_peer(const peertype & peer);

        /** init server listener on the given port */
        void setup_listener(int portno);

        /** Gracefully close the connection and free the used socket */
        void close_connection();

        /** helper to check if the socket is still valid */
        bool check_socket_status(int sock);

        /** acceptor (this is only the accept part, 
         * has to be called in a loop to be effective 
         */
        peertype acceptor(std::vector<std::string> & addresses);

        /** helper method to activate keep-alive
         * on a given socket
         */
        bool toggle_keep_alive(int toggle, int idle, int interval, int count);

        /** helper method to set timeout on a given socket */
        void set_timeout();

        /** exchange and validate config with peer */
        int check_remote_config();

        /** read only n bytes from network, and store into buf */
        bool read_n_bytes(void *buf, std::size_t n, bool tmp_socket=false, int signal=MSG_WAITALL);

        /** read a sks-type Message */
        Message* read_message(bool tmp_socket=false, int signal=MSG_WAITALL);

        Message* read_message_async();

        /** perform the actual send */
        void send_peer(Buffer& buf, bool tmp_socket=false);

    	/** send a message to the other peer */
        void send_message(Message*, bool tmp_socket=false);

    	/** send a series of messages to the other peer */
        void send_bulk_messages(std::vector<Message*> &);

	    /** send a message without header */
        void send_message_direct(Message*);

        /** direct read a string from the network */
        std::string read_string_direct();

        /** send a sks-type message */
        void write_message(Buffer &buffer, Message* m, bool wrap=true);

	    /** fail accordingly to the error passed */
        void early_fail(std::string);

};

#endif
