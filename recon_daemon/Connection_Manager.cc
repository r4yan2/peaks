#include "Connection_Manager.h"
using namespace Utils;

Connection_Manager::Connection_Manager(){}
Connection_Manager::~Connection_Manager(){}

void Connection_Manager::setup_listener(int portno){
    struct sockaddr_in serv_addr; 

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0)
        g_logger.log(Logger_level::CRITICAL, "error on binding");
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

std::pair<bool, peertype> Connection_Manager::acceptor(std::vector<std::string> addresses){
    peertype remote_peer;
    int connfd = 0;
    struct sockaddr_in client_addr;
    socklen_t clilen = sizeof(client_addr);
    connfd = accept(listenfd, (struct sockaddr*)&client_addr, &clilen);
    if (connfd < 0){
        g_logger.log(Logger_level::WARNING, "Error on accept");
        return std::make_pair(false, remote_peer);
    }
    struct sockaddr_in* pV4Addr = (struct sockaddr_in*)&client_addr;
    struct in_addr ipAddr = pV4Addr->sin_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop( AF_INET, &ipAddr, ip_str, INET_ADDRSTRLEN );
    std::vector<std::string>::iterator it = find(addresses.begin(), addresses.end(), ip_str);
    int pos = it - addresses.begin();
    if (pos >= addresses.size()){
        // ip does not belong to membership
        g_logger.log(Logger_level::WARNING, std::string(ip_str) + " blocked because not in membership");
        close(connfd);
        return std::make_pair(false, remote_peer);
        }
    // set keep alive for 1 minute
    if (!(toggle_keep_alive(connfd, 1, 1, 1, 60)))
        g_logger.log(Logger_level::WARNING, "could not enable keep alive");
    int remote_port = check_remote_config();
    if (remote_port < 0)
        return std::make_pair(false, remote_peer);
    g_logger.log(Logger_level::DEBUG, "connection accepted and configured correctly");
    remote_peer = std::make_pair(std::string(ip_str), remote_port);
    return std::make_pair(true, remote_peer);
}

void Connection_Manager::set_timeout(int socket, unsigned int timeout){
  struct timeval tv;
  tv.tv_sec  = timeout;
  tv.tv_usec = 0;
  setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}


bool Connection_Manager::toggle_keep_alive(int socket, int toggle, int idle, int interval, int count){
    if (setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &toggle, sizeof(toggle)) < 0)
        return false;
    
    if (toggle)
    {
        /* Set the number of seconds the connection must be idle before sending a KA probe. */
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0)
            return false;

        /* Set how often in seconds to resend an unacked KA probe. */
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) < 0)
            return false;
    
        /* Set how many times to resend a KA probe if previous probe was unacked. */
        if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count)) < 0)
            return false;
    }
    return true;
    
}

void Connection_Manager::init(peertype peer){
    int portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    std::string hostname;

    hostname = peer.first;
    portno = peer.second;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        g_logger.log(Logger_level::WARNING, "ERROR opening socket");
    server = gethostbyname(hostname.c_str());
    if (server == NULL) {
        g_logger.log(Logger_level::WARNING, "ERROR, no such host");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
    (char *)&serv_addr.sin_addr.s_addr,
    server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        g_logger.log(Logger_level::WARNING, "ERROR connecting");
    g_logger.log(Logger_level::DEBUG, "connected succesfully to remote peer");
    set_timeout(sockfd, 300);
}


int Connection_Manager::check_remote_config(){

    g_logger.log(Logger_level::DEBUG, "checking remote config");
    Peer_config* local_config = new Peer_config;
    local_config->version = Recon_settings::peaks_version;
    local_config->http_port = Recon_settings::peaks_port;
    local_config->bq = Recon_settings::bq;
    local_config->mbar = Recon_settings::mbar;
    local_config->filters = Recon_settings::peaks_filters;

    g_logger.log(Logger_level::DEBUG, "checking remote config2");

    write_message(local_config);

    g_logger.log(Logger_level::DEBUG, "checking remote config3");

    Peer_config* remote_config = (Peer_config*) read_message();

    g_logger.log(Logger_level::DEBUG, "checking remote config4");

    if (remote_config->bq != local_config->bq){
        buftype buf;
        Config_mismatch* msg = new Config_mismatch;
        msg->reason = "mismatched bitquantum";
        msg->marshal(buf);
        send_message(buf);
        return -1;
    }
    else if (remote_config->mbar != local_config->mbar){
        buftype buf;
        Config_mismatch* msg = new Config_mismatch;
        msg->reason = "mismatched mbar";
        msg->marshal(buf);
        send_message(buf);
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
    write_message(msg, false);

    //read config ack
    std::string remote_status = read_string_direct();
    if (strcmp(remote_status.c_str(),"passed")){
        std::string reason = read_string_direct();
        g_logger.log(Logger_level::WARNING, "remote host rejected config, status: " + remote_status + " reason: " + reason);
        return -1;
    }
    g_logger.log(Logger_level::DEBUG, "checking remote config successful");
    
    return remote_config->http_port;
}

bool Connection_Manager::read_n_bytes(void *buf, std::size_t n) {
    std::size_t offset = 0;
    char *cbuf = reinterpret_cast<char*>(buf);
    while (true) {
        ssize_t ret = recv(sockfd, cbuf + offset, n - offset, MSG_WAITALL);
        if (ret < 0 && errno != EINTR) {
            // IOException
            g_logger.log(Logger_level::CRITICAL, "IOException on recv");
            throw std::invalid_argument(strerror(errno));
        } else if (ret == 0) {
            // No data available anymore
            if (offset == 0){
                g_logger.log(Logger_level::WARNING, "No more data");   
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
   if (read_n_bytes(&size, sizeof(size))) {
       size = Utils::swap(size);
       g_logger.log(Logger_level::DEBUG, "remote string size: " + std::to_string(size));
       if (size > Recon_settings::max_read_len) g_logger.log(Logger_level::WARNING, "Oversized message!");
       g_logger.log(Logger_level::DEBUG, "fetching remote host status confirmation");
       buftype buf(size);
       read_n_bytes(buf.data(), size);
       res = buf.to_str();
   } else
       g_logger.log(Logger_level::WARNING, "Unexpected end of stream");
   return res;
}

// Reads message from network
Message* Connection_Manager::read_message() {
   std::uint32_t size;
   if (read_n_bytes(&size, sizeof(size))) {
       g_logger.log(Logger_level::DEBUG, "read 4 bytes ok");
       size = Utils::swap(size);
       if (size > Recon_settings::max_read_len) g_logger.log(Logger_level::WARNING, "Oversized message!");
       Buffer ibuf(size);
       if (read_n_bytes(ibuf.data(), size)) {
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
                case Msg_type::ErrorType: {
                            ErrorType* data = new ErrorType;
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
}

void Connection_Manager::write_message(Message* m, bool wrap){
    buftype buffer;
    if (wrap)
        buffer.push_back((unsigned char)m->type);
    g_logger.log(Logger_level::DEBUG, "Preparing to write message type" + std::to_string(m->type));
    switch(m->type){
        case Msg_type::ReconRequestPoly:{
                                            ((ReconRequestPoly*)m)->marshal(buffer);
                                            break;
                                        }
        case Msg_type::ReconRequestFull:{
                                            ((ReconRequestFull*)m)->marshal(buffer);
                                            break;
                                        }
        case Msg_type::Elements:{
                                    ((Elements*)m)->marshal(buffer);
                                    break;
                                }
        case Msg_type::FullElements:{
                                    ((FullElements*)m)->marshal(buffer);
                                    break;
                                    }
        case Msg_type::ErrorType:{
                                     ((FullElements*)m)->marshal(buffer);
                                     break;
                                 }
        case Msg_type::DBRequest:{
                                     ((DBRequest*)m)->marshal(buffer);
                                     break;
                                 }
        case Msg_type::DBReply:{
                                   ((DBReply*)m)->marshal(buffer);
                                   break;
                               }
        case Msg_type::Peer_config:{
                                       ((Peer_config*)m)->marshal(buffer);
                                       break;
                                   }
        case Msg_type::Config_mismatch:{
                                           ((Config_mismatch*)m)->marshal(buffer);
                                           break;
                                       }
        case Msg_type::Config_ok:{
                                     ((Config_ok*)m)->marshal(buffer);
                                      break;
                                      }
        default:
                                 g_logger.log(Logger_level::CRITICAL, "Output message not recognized");
    }
    if (wrap)
        buffer.write_self_len();
    send_message(buffer);
}

void Connection_Manager::send_message(buftype &buf){
    int err = send(sockfd, buf.data(), buf.size(), MSG_NOSIGNAL);
    g_logger.log(Logger_level::DEBUG, std::to_string(buf.size()));
    if (err < 0)
        throw send_message_exception(); 
    g_logger.log(Logger_level::DEBUG, "data sent ok");
}

