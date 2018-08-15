#ifndef RECON_PEER_H
#define RECON_PEER_H
#include "Recon_settings.h"
#include "Utils.h"
#include <random>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include <NTL/matrix.h>
#include "Connection_Manager.h"
#include "pTreeDB.h"
#include "exception.h"
#include <cmath>
#include <NTL/mat_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ_pXFactoring.h>
#include <algorithm>
#include "logger.h"
#include <thread>
#include <deque>
#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>
#include <curlpp/Exception.hpp>
#include "../dump_import/dump_import.h"
#include <unistd.h>
#include <chrono>

/*
 * this will be send via networking
 * to the other peer for config
 * syncronization before actual
 * gossiping can occur
 */

enum class Communication_status {NONE, ERROR, DONE};

struct Communication{
    zset samples;
    bool send;
    Communication_status status;
    std::vector<Message*> messages;
    Communication():send(false), status(Communication_status::NONE){}
};

struct request_entry{
    Pnode* node;
    bitset key;
};

namespace recon_state{
enum recon_state: int {Bottom=0, FlushEnded=1};
}

struct bottom_entry{
    request_entry request;
    uint8_t state;
};

class Peer{
    private:
        /** hold the Connection Manager reference*/
        Connection_Manager cn;
        /** hold the ptree reference */
        Ptree tree;
        /** hold the list of peers specified in membership file */
        std::vector<peertype> membership;
    public:
        /** constructor take a ptree on which operate */ 
        Peer(Ptree new_tree);

        /** choose random peer partner among the
         * one specified in membership
         */
        peertype choose_partner();

        /** start recon daemon processes */
        void start();

        /** recon as client with choosen peer */
        void client_recon(peertype);

        void gossip(); /**< recon as client */

        void serve(); /**< recon as server */

        std::vector<NTL::ZZ_p> interact_with_client(peertype remote_peer);

        /** fetch the given element from the peer */
        void fetch_elements(peertype peer, std::vector<NTL::ZZ_p> elems);

        Communication request_poly_handler(ReconRequestPoly* req);
        Communication request_full_handler(ReconRequestFull* req);
        std::pair<std::vector<NTL::ZZ_p>,std::vector<NTL::ZZ_p>> solve(std::vector<NTL::ZZ_p> r_samples, int r_size, std::vector<NTL::ZZ_p> l_samples, int l_size, std::vector<NTL::ZZ_p> points);

        std::vector<std::string> request_chunk(peertype peer, std::vector<NTL::ZZ_p> elements);
};

class Recon_manager{
    private:
        std::deque<request_entry> request_queue;
        std::deque<bottom_entry> bottom_queue;
        zset remote_set;
        bool flushing=false;
        std::vector<Message*> messages;
        Connection_Manager cn;
        int clientfd;
    public:
        Recon_manager(Connection_Manager conn_manager);
        ~Recon_manager();
        void push_bottom(bottom_entry bottom);
        void prepend_request(request_entry requests);
        void push_request(request_entry request);
        bottom_entry top_bottom();
        bottom_entry pop_bottom();
        request_entry pop_request();
        bool done();
        bool bottom_queue_empty();
        void send_request(request_entry request);
        void handle_reply(Message* msg,request_entry request);
        void flush_queue();
        void toggle_flush(bool new_state);
        int bottom_queue_size();
        int request_queue_size();
        bool is_flushing();
        std::vector<NTL::ZZ_p> elements();
};

#endif //RECON_PEER_H 
