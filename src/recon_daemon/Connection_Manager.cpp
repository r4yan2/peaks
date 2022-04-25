#include "Connection_Manager.h"
#include <common/config.h>
#include <common/utils.h>

using namespace peaks::common;
namespace peaks{
namespace recon{

Peer::Peer(const char* _hostname, int _port):
    hostname(_hostname),
    port(_port)
{}

Peer::Peer(const std::string & _hostname, int _port):
    hostname(_hostname),
    port(_port)
{}

Connection::Connection(std::mutex & _m, const char* _hostname, int _port, int _socket):
    m(_m),
    peer(_hostname, _port),
    sockfd(_socket)
{}
Connection::Connection(std::mutex & _m, const char* _hostname, int _socket):
    m(_m),
    peer(_hostname, -1),
    sockfd(_socket)
{}
Connection::Connection(std::mutex & _m, const std::string & _hostname, int _port, int _socket):
   m(_m),
   peer(_hostname, _port),
   sockfd(_socket)
{}
Connection::Connection(std::mutex & _m, const std::string & _hostname, int _socket):
   m(_m),
   peer(_hostname, -1),
   sockfd(_socket)
{}
Connection_Manager::Connection_Manager():
    listenfd(-1)
{}

void Connection_Manager::setup_listener(int portno){
    struct sockaddr_in serv_addr; 

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0){
        syslog(LOG_CRIT, "error on binding");
        throw (std::runtime_error("error on binding"));
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(portno); 

    int err = bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 
    if (err < 0)
        syslog(LOG_CRIT, "error on bind!");
    syslog(LOG_DEBUG, "binding ok, proceed to listen for incoming connections");
    err = listen(listenfd, 10);
    if (err < 0)
        syslog(LOG_CRIT, "error on bind!");
    syslog(LOG_DEBUG, "listen ok");
}

Connection Connection_Manager::acceptor(std::vector<std::string> & addresses){
    struct sockaddr_in client_addr;
    socklen_t clilen = sizeof(client_addr);
    int tmpfd = accept(listenfd, (struct sockaddr*)&client_addr, &clilen);
    if (tmpfd < 0)
    {
        syslog(LOG_WARNING, "error on accept");
        throw Bad_client();
    }
    struct sockaddr_in* pV4Addr = (struct sockaddr_in*)&client_addr;
    struct in_addr ipAddr = pV4Addr->sin_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop( AF_INET, &ipAddr, ip_str, INET_ADDRSTRLEN);
    auto it = find(addresses.begin(), addresses.end(), ip_str);
    if (it == addresses.end()){
        // ip does not belong to membership
        syslog(LOG_WARNING, "blocked %s because not in membership", ip_str);
        close(tmpfd);
        throw Bad_client();
        }
    Connection client_conn(mtx, ip_str, tmpfd);
    if (!client_conn.check_remote_config())
        throw Bad_client();
    return client_conn;
}

void Connection::set_timeout(){
  struct timeval tv;
  tv.tv_sec  = CONTEXT.connsettings.async_timeout_sec;
  tv.tv_usec = CONTEXT.connsettings.async_timeout_usec;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void Connection::early_fail(std::string reason){

    syslog(LOG_WARNING, "Config mismatch, reason: %s", reason.c_str());
    Buffer buf;
    Config_mismatch* msg = new Config_mismatch;
    msg->reason = reason;
    msg->marshal(buf);
    send_peer(buf);
}

bool Connection::toggle_keep_alive(int toggle, int idle, int interval, int count){
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &toggle, sizeof(toggle)) < 0)
        return false;
    
    if (toggle)
    {
        /* Set the number of seconds the connection must be idle before sending a KA probe. */
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0)
            return false;

        /* Set how often in seconds to resend an unacked KA probe. */
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) < 0)
            return false;
    
        /* Set how many times to resend a KA probe if previous probe was unacked. */
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count)) < 0)
            return false;
    }
    return true;
}

Connection Connection_Manager::init_peer(const member & peer){
    struct sockaddr_in serv_addr;
    struct hostent *server;
    std::string hostname;

    int tmpfd = socket(AF_INET, SOCK_STREAM, 0);
    if (tmpfd < 0)
        throw connection_exception("ERROR opening socket");
    syslog(LOG_DEBUG, "Socket open ok");
    server = gethostbyname(peer.first.c_str());
    if (server == NULL) {
        throw connection_exception("ERROR connecting: no such host");
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
    (char *)&serv_addr.sin_addr.s_addr,
    server->h_length);
    serv_addr.sin_port = htons(peer.second);
    int err = connect(tmpfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr));
    if (err < 0)
        throw connection_exception("ERROR connecting");
    syslog(LOG_DEBUG, "Connect ok");
    return Connection(mtx, peer.first, peer.second, tmpfd);
}


Connection::~Connection(){
    syslog(LOG_DEBUG, "closing remote connection %d", sockfd);
    shutdown(sockfd, 2);
    close(sockfd);
    m.unlock();
}

Peer Connection::get_peer(){
    return peer;
}

bool Connection::check_remote_config(){

    Peer_config* local_config = new Peer_config;
    local_config->version = CONTEXT.connsettings.peaks_version;
    local_config->http_port = CONTEXT.connsettings.peaks_http_port;
    local_config->bq = CONTEXT.treesettings.bq;
    local_config->mbar = CONTEXT.treesettings.mbar;
    local_config->filters = CONTEXT.connsettings.peaks_filters;

    send_message(local_config);

    Peer_config* remote_config = (Peer_config*) read_message();
    syslog(LOG_DEBUG, "received remote config");

    if (!m.try_lock()){
        early_fail("sync already in progress");
        return false;
    }
    
    if (remote_config->bq != local_config->bq){
        early_fail("mismatched bitquantum");
        return false;
    }
    else if (remote_config->mbar != local_config->mbar){
        early_fail("mismatched mbar");
        return false;
    }

    //send config ack
    Config_ok* msg = new Config_ok;
    send_message_direct(msg);

    //read config ack
    std::string remote_status = read_string_direct();
    if (strcmp(remote_status.c_str(),"passed")){
        std::string reason = read_string_direct();

        syslog(LOG_WARNING, "remote host rejected config, reason: %s", reason.c_str());
        return false;
    }
    syslog(LOG_DEBUG, "Config check ok");

    int http_port = remote_config->http_port;
    peer.port = http_port;
    delete local_config;
    delete remote_config;

    if (http_port < 0)
        throw Bad_client();
    // set keep alive for 1 minute
    if (!(toggle_keep_alive(1, 1, 1, 60)))
        syslog(LOG_WARNING, "could not enable keep alive");
    
    set_timeout();
    return true;
}

bool Connection::check_socket_status(){
    int err=0;
    socklen_t len = sizeof(err);
    int ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0 || ret != 0)
        return false;
    else
        return true;
}

bool Connection::read_n_bytes(void *buf, std::size_t n, int signal){
    std::size_t offset = 0;
    char *cbuf = reinterpret_cast<char*>(buf);
    ssize_t ret;
    while (true) {
        ret = recv(sockfd, cbuf + offset, n - offset, signal);
        if (ret < 0){
            std::string errmsg = "";
            switch(errno){
                //EAGAIN have the same number as EWOULDBLOCK, but for portability should be checked separately
                case EWOULDBLOCK:
				        errmsg = "Receive operation would block, try to raise the timeout";
                        break;
                case EBADF:
				        errmsg = "The given socket is an invalid descriptor";
                        break;
                case ECONNREFUSED:
				        errmsg = "A remote host refused to allow the network connection (typically because it is not running the requested service).";
                        break;
				case EFAULT:
				        errmsg = "The receive buffer pointer(s) point outside the process's address space.";
                        break;
                case EINTR:
				        errmsg = "The receive was interrupted by delivery of a signal before any data were available; see signal(7).";
                        break;
                case EINVAL:
				        errmsg = "Invalid argument passed.";
                        break;
                case ENOMEM:
				        errmsg = "Could not allocate memory for recvmsg().";
                        break;
                case ENOTCONN:
				        errmsg = "The socket is associated with a connection-oriented protocol and has not been connected";
                        break;
                case ENOTSOCK:
				        errmsg = "The argument sockfd does not refer to a socket.";
                        break;
                default:
                        errmsg = "Unkown error on recv";
            }
            syslog(LOG_DEBUG, "%s (%d)", errmsg.c_str(), errno);
            throw std::invalid_argument(strerror(errno));
        } else if (ret == 0) {
            // No data available
            if (offset == 0){
                syslog(LOG_WARNING, "No data available, Expected: %d, Got: %d", int(n), int(offset+ret));   
                return false;
            }else{
                //Protocol Exception
                syslog(LOG_WARNING, "Underflow on recv");
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

std::string Connection::read_string_direct(){
   std::uint32_t size;
   std::string res = "failed";
   if (read_n_bytes(&size, sizeof(size))) {
       size = Utils::swap(size);
       if (size > CONTEXT.connsettings.max_read_len) 
           syslog(LOG_WARNING, "Oversized message!");
       Buffer buf(size);
       read_n_bytes(buf.data(), size);
       res = buf.to_str();
   } else
       syslog(LOG_WARNING, "Unexpected end of stream");
   return res;
}

Message* Connection::read_message_async(){
    return read_message(0);//MSG_DONTWAIT);
}

// Reads message from network
Message* Connection::read_message(int signal) {
   std::uint32_t size;
   if (read_n_bytes(&size, sizeof(size), signal)) {
       size = Utils::swap(size);
       if (size > CONTEXT.connsettings.max_read_len) 
           syslog(LOG_WARNING, "Oversized message!");
       Buffer ibuf(size);
       if (read_n_bytes(ibuf.data(), size, signal)) {
           ibuf.set_read_only();
           uint8_t type = ibuf.read_uint8();
           switch (type){
                case Msg_type::ReconRequestPoly: {
                            ReconRequestPoly* data = new ReconRequestPoly;
                            data->unmarshal(ibuf);
                            data->type=type;
                            return data;
                        }
                case Msg_type::ReconRequestFull: {
                            ReconRequestFull* data = new ReconRequestFull;
                            data->unmarshal(ibuf);
                            data->type=type;
                            return data;
                        }
                case Msg_type::Elements: {
                            Elements* data = new Elements;
                            data->unmarshal(ibuf);
                            data->type=type;
                            return data;
                        }
                case Msg_type::FullElements: {
                            FullElements* data = new FullElements;
                            data->unmarshal(ibuf);
                            data->type=type;
                            return data;
                        }
                case Msg_type::SyncFail: {
                            SyncFail* data = new SyncFail;
                            data->unmarshal(ibuf);
                            data->type=type;
                            return data;
                        }
                case Msg_type::Done: {
                            Done* data = new Done;
                            data->unmarshal(ibuf);
                            data->type=type;
                            return data;
                        }
                case Msg_type::Flush: {
                            Flush* data = new Flush;
                            data->unmarshal(ibuf);
                            data->type=type;
                            return data;
                        }
                case Msg_type::Error: {
                            Error* data = new Error;
                            data->unmarshal(ibuf);
                            data->type=type;
                            return data;
                        }
                case Msg_type::DBRequest: {
                            DBRequest* data = new DBRequest;
                            data->unmarshal(ibuf);
                            data->type=type;
                            return data;
                        }
                case Msg_type::DBReply: {
                            DBReply* data = new DBReply;
                            data->unmarshal(ibuf);
                            data->type=type;
                            return data;
                        }
                case Msg_type::Peer_config: {
                             Peer_config* data = new Peer_config;
                             data->unmarshal(ibuf);
                             data->type=type;
                             return data;
                            }
                             
                default: syslog(LOG_WARNING, "Cannot understand message type during recon!");
        }

       } else {
           //Protocol Exception
           syslog(LOG_WARNING, "Unexpected end of stream");
           throw std::underflow_error("Unexpected end of stream");
       }
   } else {
       // connection was closed
       syslog(LOG_WARNING, "Unexpected end of stream");
       throw std::underflow_error("Unexpected end of stream");
   }
   Error* data = new Error;
   return data;
}

void Connection::write_message(Buffer &buffer, Message* m, bool wrap){
    Buffer partial_buffer;
    if (wrap)
        partial_buffer.push_back((unsigned char)m->type);
    switch(m->type){
        case Msg_type::ReconRequestPoly:
            ((ReconRequestPoly*)m)->marshal(partial_buffer);
            delete ((ReconRequestPoly*) m);
            break;
                                        
        case Msg_type::ReconRequestFull:
            ((ReconRequestFull*)m)->marshal(partial_buffer);
            delete ((ReconRequestFull*) m);
            break;

        case Msg_type::Elements:
            ((Elements*)m)->marshal(partial_buffer);
            delete ((Elements*) m);
            break;
                                
        case Msg_type::FullElements:
            ((FullElements*)m)->marshal(partial_buffer);
            delete ((FullElements*) m);
            break;
                                    
        case Msg_type::SyncFail:
            ((SyncFail*)m)->marshal(partial_buffer);
            delete ((SyncFail*) m);
            break;

        case Msg_type::Error:
            ((Error*)m)->marshal(partial_buffer);
            delete ((Error*) m);
            break;
                                 
        case Msg_type::DBRequest:
            ((DBRequest*)m)->marshal(partial_buffer);
            delete ((DBRequest*) m);
            break;
                                 
        case Msg_type::DBReply:
            ((DBReply*)m)->marshal(partial_buffer);
            delete ((DBReply*) m);
            break;
                               
        case Msg_type::Peer_config:
            ((Peer_config*)m)->marshal(partial_buffer);
                                       //delete ((Peer_config*) m);
            break;
                                   
        case Msg_type::Config_mismatch:
            ((Config_mismatch*)m)->marshal(partial_buffer);
            delete ((Config_mismatch*) m);
            break;
                                       
        case Msg_type::Config_ok:
            ((Config_ok*)m)->marshal(partial_buffer);
            delete ((Config_ok*) m);
            break;
        case Msg_type::Done:
            break; //empty
        case Msg_type::Flush:
            break; //empty
        default:
            syslog(LOG_ERR, "Unrecognized Message %d", m->type);
            break;
    }
    if (wrap)
        partial_buffer.write_self_len();
    buffer.append(partial_buffer);
}

void Connection::send_message_direct(Message* m){
    Buffer buf;
    write_message(buf, m, false);
    send_peer(buf);
}

void Connection::send_message(Message* m){
    Buffer buf;
    write_message(buf,m);
    send_peer(buf);
}

void Connection::send_bulk_messages(std::vector<Message*> messages){
    Buffer buf;
    for (Message* m: messages)
        write_message(buf, m);
    send_peer(buf);
}

void Connection::send_peer(Buffer &buf){
    int err = send(sockfd, buf.data(), buf.size(), MSG_NOSIGNAL);
    if (err < 0)
        throw send_message_exception(); 
}

}
}
