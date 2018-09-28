#include "Connection_Manager.h"
using namespace Utils;

Connection_Manager::Connection_Manager(){}
Connection_Manager::~Connection_Manager(){}

void Connection_Manager::setup_listener(int portno){
    struct sockaddr_in serv_addr; 

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0){
        g_logger.log(Logger_level::CRITICAL, "error on binding");
        throw (std::runtime_error("error on binding"));
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(portno); 

    int err = bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 
    if (err < 0)
        g_logger.log(Logger_level::CRITICAL, "error on binding");
    g_logger.log(Logger_level::DEBUG, "binding ok, proceed to listen for incoming connections");
    listen(listenfd, 10);
}

std::pair<bool,peertype> Connection_Manager::acceptor(std::vector<std::string> addresses){
    peertype remote_peer;
    struct sockaddr_in client_addr;
    socklen_t clilen = sizeof(client_addr);
    tmpfd = accept(listenfd, (struct sockaddr*)&client_addr, &clilen);
    if (tmpfd < 0){
        g_logger.log(Logger_level::WARNING, "Error on accept");
        return std::make_pair(false, remote_peer);
    }
    struct sockaddr_in* pV4Addr = (struct sockaddr_in*)&client_addr;
    struct in_addr ipAddr = pV4Addr->sin_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop( AF_INET, &ipAddr, ip_str, INET_ADDRSTRLEN );
    std::vector<std::string>::iterator it = find(addresses.begin(), addresses.end(), ip_str);
    size_t pos = it - addresses.begin();
    if (pos >= addresses.size()){
        // ip does not belong to membership
        g_logger.log(Logger_level::WARNING, std::string(ip_str) + " blocked because not in membership");
        close(tmpfd);
        return std::make_pair(false, remote_peer);
        }
    int remote_port = check_remote_config();
    if (remote_port < 0)
        return std::make_pair(false, remote_peer);
    g_logger.log(Logger_level::DEBUG, "connection accepted and configured correctly");
    remote_peer = std::make_pair(std::string(ip_str), remote_port);
    return std::make_pair(true, remote_peer);
}

void Connection_Manager::set_timeout(){
  struct timeval tv;
  tv.tv_sec  = recon_settings.async_timeout_sec;
  tv.tv_usec = recon_settings.async_timeout_usec;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

void Connection_Manager::early_fail(std::string reason){

    g_logger.log(Logger_level::DEBUG, "Config mismatch, reason: " + reason);
    Buffer buf;
    Config_mismatch* msg = new Config_mismatch;
    msg->reason = reason;
    msg->marshal(buf);
    send_peer(buf);
}

bool Connection_Manager::toggle_keep_alive(int toggle, int idle, int interval, int count){
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

int Connection_Manager::init_peer(peertype peer){
    int portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    std::string hostname;

    hostname = peer.first;
    portno = peer.second;
    tmpfd = socket(AF_INET, SOCK_STREAM, 0);
    if (tmpfd < 0)
        throw connection_exception("ERROR opening socket");
    server = gethostbyname(hostname.c_str());
    if (server == NULL) {
        throw connection_exception("ERROR connecting: no such host");
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
    (char *)&serv_addr.sin_addr.s_addr,
    server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(tmpfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        throw connection_exception("ERROR connecting");
    g_logger.log(Logger_level::DEBUG, "connected succesfully to remote peer");
    return check_remote_config();
}

void Connection_Manager::close_connection(){
    shutdown(sockfd, 2);
    close(sockfd);
    sockfd = -1;
    g_logger.log(Logger_level::DEBUG, "connection closed succesfully");
}


int Connection_Manager::check_remote_config(){

    g_logger.log(Logger_level::DEBUG, "checking remote config 1/4");
    Peer_config* local_config = new Peer_config;
    local_config->version = recon_settings.peaks_version;
    local_config->http_port = recon_settings.peaks_http_port;
    local_config->bq = recon_settings.bq;
    local_config->mbar = recon_settings.mbar;
    local_config->filters = recon_settings.peaks_filters;

    g_logger.log(Logger_level::DEBUG, "checking remote config 2/4");

    send_message(local_config, true);

    g_logger.log(Logger_level::DEBUG, "checking remote config 3/4");

    Peer_config* remote_config = (Peer_config*) read_message(true);

    g_logger.log(Logger_level::DEBUG, "checking remote config 4/4");
    
    if (sockfd > 0 && check_socket_status(sockfd)){
        early_fail("currently mutating");
        return -1;
    }
    if (remote_config->bq != local_config->bq){
        early_fail("mismatched bitquantum");
        return -1;
    }
    else if (remote_config->mbar != local_config->mbar){
        early_fail("mismatched mbar");
        return -1;
    }

    g_logger.log(Logger_level::DEBUG, 
            "checking remote config successful" +
            std::string(", version= ") + remote_config->version + 
            ", mbar= " + std::to_string(remote_config->mbar) + 
            ", bq = " + std::to_string(remote_config->bq) + 
            ", filters= "  + remote_config->filters + 
            ", other = " + std::to_string(remote_config->other.size())
            );

    //send config ack
    Config_ok* msg = new Config_ok;
    send_message_direct(msg);

    //read config ack
    std::string remote_status = read_string_direct();
    if (strcmp(remote_status.c_str(),"passed")){
        std::string reason = read_string_direct();
        g_logger.log(Logger_level::WARNING, "remote host rejected config, status: " + remote_status + " reason: " + reason);
        return -1;
    }
    g_logger.log(Logger_level::DEBUG, "checking remote config successful");

    int http_port = remote_config->http_port;
    delete local_config;
    delete remote_config;

    // if all check are passed tmpfd is promoted to the active socket
    sockfd = tmpfd;
    tmpfd = -1;

    // set keep alive for 1 minute
    if (!(toggle_keep_alive(1, 1, 1, 60)))
        g_logger.log(Logger_level::WARNING, "could not enable keep alive");
    
    set_timeout();
    
    return http_port;
}

bool Connection_Manager::check_socket_status(int sock){
    int err=0;
    socklen_t len = sizeof(err);
    int ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0 || ret != 0)
        return false;
    else
        return true;
}

bool Connection_Manager::read_n_bytes(void *buf, std::size_t n, bool tmp_socket, int signal){
    std::size_t offset = 0;
    char *cbuf = reinterpret_cast<char*>(buf);
    ssize_t ret;
    while (true) {
        if (tmp_socket)
            ret = recv(tmpfd, cbuf + offset, n - offset, signal);
        else
            ret = recv(sockfd, cbuf + offset, n - offset, signal);
        if (ret < 0 && (errno != EINTR || errno != EWOULDBLOCK || errno != EAGAIN)) {
            // IOException
            g_logger.log(Logger_level::CRITICAL, "IOException on recv");
            throw std::invalid_argument(strerror(errno));
        } else if (ret == 0) {
            // No data available
            if (offset == 0){
                g_logger.log(Logger_level::WARNING, "No data available, Expected: " + std::to_string(n) + " Got: " + std::to_string(offset+ret));   
                return false;
            }else{
                //Protocol Exception
                g_logger.log(Logger_level::WARNING, "Underflow on recv");
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

std::string Connection_Manager::read_string_direct(){
   std::uint32_t size;
   std::string res = "failed";
   if (read_n_bytes(&size, sizeof(size), true)) {
       size = Utils::swap(size);
       g_logger.log(Logger_level::DEBUG, "remote string size: " + std::to_string(size));
       if (size > recon_settings.max_read_len) g_logger.log(Logger_level::WARNING, "Oversized message!");
       g_logger.log(Logger_level::DEBUG, "fetching remote host status confirmation");
       Buffer buf(size);
       read_n_bytes(buf.data(), size, true);
       res = buf.to_str();
   } else
       g_logger.log(Logger_level::WARNING, "Unexpected end of stream");
   return res;
}

Message* Connection_Manager::read_message_async(){
    return read_message(false, 0);
}

// Reads message from network
Message* Connection_Manager::read_message(bool tmp_socket, int signal) {
   std::uint32_t size;
   if (read_n_bytes(&size, sizeof(size), tmp_socket, signal)) {
       g_logger.log(Logger_level::DEBUG, "read 4 bytes ok");
       size = Utils::swap(size);
       if (size > recon_settings.max_read_len) g_logger.log(Logger_level::WARNING, "Oversized message!");
       Buffer ibuf(size);
       if (read_n_bytes(ibuf.data(), size, tmp_socket, signal)) {
       g_logger.log(Logger_level::DEBUG, "read " + std::to_string(size) +" bytes ok");
           ibuf.set_read_only();
           uint8_t type = ibuf.read_uint8();
           g_logger.log(Logger_level::DEBUG, "unpacking message type" + std::to_string(type));
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
                             
                default: g_logger.log(Logger_level::WARNING, "Cannot understand message type during recon!");
        }

       } else {
           //Protocol Exception
           g_logger.log(Logger_level::WARNING, "Unexpected end of stream");
           throw std::underflow_error("Unexpected end of stream");
       }
   } else {
       // connection was closed
       g_logger.log(Logger_level::WARNING, "Unexpected end of stream");
       throw std::underflow_error("Unexpected end of stream");
   }
   Error* data = new Error;
   return data;
}

void Connection_Manager::write_message(Buffer &buffer, Message* m, bool wrap){
    Buffer partial_buffer;
    if (wrap)
        partial_buffer.push_back((unsigned char)m->type);
    g_logger.log(Logger_level::DEBUG, "Preparing to write message type" + std::to_string(m->type));
    switch(m->type){
        case Msg_type::ReconRequestPoly:{
                                            ((ReconRequestPoly*)m)->marshal(partial_buffer);
                                            delete ((ReconRequestPoly*) m);
                                            break;
                                        }
        case Msg_type::ReconRequestFull:{
                                            ((ReconRequestFull*)m)->marshal(partial_buffer);
                                            delete ((ReconRequestFull*) m);
                                            break;
                                        }
        case Msg_type::Elements:{
                                    ((Elements*)m)->marshal(partial_buffer);
                                    delete ((Elements*) m);
                                    break;
                                }
        case Msg_type::FullElements:{
                                    ((FullElements*)m)->marshal(partial_buffer);
                                    delete ((FullElements*) m);
                                    break;
                                    }
        case Msg_type::Error:{
                                     ((Error*)m)->marshal(partial_buffer);
                                     delete ((Error*) m);
                                     break;
                                 }
        case Msg_type::DBRequest:{
                                     ((DBRequest*)m)->marshal(partial_buffer);
                                     delete ((DBRequest*) m);
                                     break;
                                 }
        case Msg_type::DBReply:{
                                   ((DBReply*)m)->marshal(partial_buffer);
                                   delete ((DBReply*) m);
                                   break;
                               }
        case Msg_type::Peer_config:{
                                       ((Peer_config*)m)->marshal(partial_buffer);
                                       //delete ((Peer_config*) m);
                                       break;
                                   }
        case Msg_type::Config_mismatch:{
                                           ((Config_mismatch*)m)->marshal(partial_buffer);
                                           delete ((Config_mismatch*) m);
                                           break;
                                       }
        case Msg_type::Config_ok:{
                                     ((Config_ok*)m)->marshal(partial_buffer);
                                     delete ((Config_ok*) m);
                                     break;
                                      }
        default:
                                 g_logger.log(Logger_level::DEBUG, "Writing message type " + std::to_string(m->type) + " which have no content...");
    }
    if (wrap)
        partial_buffer.write_self_len();
    buffer.append(partial_buffer);
    g_logger.log(Logger_level::DEBUG, "buffer filled with partial buffer");
}

void Connection_Manager::send_message_direct(Message* m){
    Buffer buf;
    write_message(buf, m, false);
    send_peer(buf, true);
}

void Connection_Manager::send_message(Message* m, bool tmp_socket){
    Buffer buf;
    write_message(buf,m);
    send_peer(buf, tmp_socket);
}

void Connection_Manager::send_bulk_messages(std::vector<Message*> messages){
    Buffer buf;
    for (Message* m: messages)
        write_message(buf, m);
    send_peer(buf);
}

void Connection_Manager::send_peer(Buffer &buf, bool tmp_socket){
    int err;
    if (tmp_socket)
        err = send(tmpfd, buf.data(), buf.size(), MSG_NOSIGNAL);
    else
        err = send(sockfd, buf.data(), buf.size(), MSG_NOSIGNAL);
    g_logger.log(Logger_level::DEBUG, "Writing message of size " + std::to_string(buf.size()));
    if (err < 0)
        throw send_message_exception(); 
    g_logger.log(Logger_level::DEBUG, "data sent ok");
}
