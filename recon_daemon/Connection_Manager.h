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

        Connection_Manager();
        void init(peertype peer);
        void setup_listener(int portno);
        std::pair<bool,peertype> acceptor(std::vector<std::string> addresses);
        bool toggle_keep_alive(int socket, int toggle, int idle, int interval, int count);
        void set_timeout(int socket, unsigned int timeout);
        int check_remote_config();
        ~Connection_Manager();
        bool read_n_bytes(void *buf, std::size_t n);
        Message* read_message();
        bitset read_bitset();
        void send_message(buftype& buf);
        std::string read_string_direct();

        void write_message(Message* m, bool wrap=true);/**< Send message to peer */
};

#endif
