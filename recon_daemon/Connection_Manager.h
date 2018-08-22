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
#include "logger.h"
#include <algorithm>
#include "Recon_settings.h"

typedef std::pair<std::string, int> peertype;
typedef Myset<NTL::ZZ_p> zset;

class Connection_Manager{
    private:
        int sockfd = -1;
        int tmpfd = -1;
        int listenfd = -1;
    public:

        /** default constructor */
        Connection_Manager();

        /** init connection as client 
         * with given peer peer */
        int init_peer(peertype peer);

        /** init server listener on the given port */
        void setup_listener(int portno);

        void close_connection();

        bool check_socket_status(int sock);

        /** acceptor (this is only the accept part, 
         * has to be called in a loop to be effective 
         */
        std::pair<bool,peertype> acceptor(std::vector<std::string> addresses);
        /** helper method to activate keep-alive
         * on a given socket
         */
        bool toggle_keep_alive(int toggle, int idle, int interval, int count);

        /** helper method to set timeout on a given socket */
        void set_timeout(unsigned int timeout);

        /** exchange and validate config with peer */
        int check_remote_config();

        /** default destructor */
        ~Connection_Manager();

        /** read only n bytes from network, and store into buf */
        bool read_n_bytes(void *buf, std::size_t n, bool tmp_socket=false, int signal=MSG_WAITALL);

        /** read a sks-type Message */
        Message* read_message(bool tmp_socket=false, int signal=MSG_WAITALL);

        Message* read_message_async();

        /** perform the actual send */
        void send_peer(Buffer& buf, bool tmp_socket=false);

        void send_message(Message*, bool tmp_socket=false);

        void send_bulk_messages(std::vector<Message*>);

        void send_message_direct(Message*);

        /** directòy read a string from the network */
        std::string read_string_direct();

        /** send a sks-type message */
        void write_message(Buffer &buffer, Message* m, bool wrap=true);


        void early_fail(std::string);
};

#endif
