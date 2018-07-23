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
#include "Recon_settings.h"
#include <algorithm>

typedef std::pair<std::string, int> peertype;
using namespace NTL;
typedef boost::dynamic_bitset<unsigned char> bitset;
typedef Myset<ZZ_p> zset;

class Connection_Manager{
    private:
        int sockfd = 0;
        int listenfd = 0;
    public:

        /** default constructor */
        Connection_Manager();

        /** init connection as client 
         * with given peer peer */
        void init(peertype peer);

        /** init server listener on the given port */
        void setup_listener(int portno);

        /** acceptor (this is only the accept part, 
         * has to be called in a loop to be effective 
         */
        std::pair<bool,peertype> acceptor(std::vector<std::string> addresses);
        /** helper method to activate keep-alive
         * on a given socket
         */
        bool toggle_keep_alive(int socket, int toggle, int idle, int interval, int count);

        /** helper method to set timeout on a given socket */
        void set_timeout(int socket, unsigned int timeout);

        /** exchange and validate config with peer */
        int check_remote_config();

        /** default destructor */
        ~Connection_Manager();

        /** read only n bytes from network, and store into buf */
        bool read_n_bytes(void *buf, std::size_t n);

        /** read a sks-type Message */
        Message* read_message();

        /** perform the actual send */
        void send_message(buftype& buf);

        /** directòy read a string from the network */
        std::string read_string_direct();

        /** send a sks-type message */
        void write_message(Message* m, bool wrap=true);
};

#endif
