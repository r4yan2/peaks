#ifndef RECON_PEER_H
#define RECON_PEER_H
#include <random>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include "Connection_Manager.h"
#include "pTreeDB.h"
#include "exception.h"
#include <thread>
#include <deque>
#include <queue>
#include <import/import.h>
#include <unistd.h>
#include <chrono>

using namespace peaks::import;
namespace peaks{
namespace recon{

/**
 * PeerManager class represent a peer during recon.
 * This class hold all the main code needed
 * for recon.
 */
class PeerManager{
    private:
        /** hold the Connection Manager reference*/
        Connection_Manager cn;
        /** hold the list of peers specified in membership file */
        std::vector<member> membership;

    public:
        /** 
         * constructor 
         */ 
        PeerManager();

        /** choose random peer partner among the
         * one specified in membership
         */
        Connection choose_partner();

        /** start recon daemon processes */
        void start();

        /** start only server recon */
        void start_server();

        /** start only client recon */
        void start_client();

        void gossip(); /**< recon as client */

        void serve(); /**< recon as server */

        /** 
         * fetch the given element from the peer 
         * @param peer peer from which to fetch elements
         * @param elems elements to recover
         */
        void fetch_elements(const Peer &peer, const std::vector<NTL::ZZ_p> &elems);

        /** method used to request a chunk of data from the other peer
         * @param peer peer to send requests to
         * @param elemnts elements to request
         * @return vector which contains the requested elements
         */
        std::vector<std::string> request_chunk(const Peer &peer, const std::vector<NTL::ZZ_p> &elements);

};

struct request_entry{
    std::shared_ptr<Pnode> node;
    bitset key;
};

namespace recon_state{
    enum recon_state: int {Bottom=0, FlushEnded=1};
}

struct bottom_entry{
    request_entry request;
    uint8_t state;
};


/**
 * Manage the messages queue during recon
 */
class Recon_manager{
    private:
        /** queue used to keep track of message */
        std::deque<request_entry> request_queue;
        
        /** queue used to keep track of message */
        std::queue<bottom_entry> bottom_queue;

        /** track the remote peer key set */
        zpset remote_set;

        /** used to know when to flush pending messages */
        bool flushing=false;

        /** vector keeps current pending messages */
        std::vector<recon::Message*> messages;

    public:

        /** push value to the bottom queue
         * @param bottom value to push
         */
        void push_bottom(bottom_entry &bottom);

        /** prepend request in the request_queue
         * @param request request entry to prepend
         */
        void prepend_request(request_entry &request);

        /** push reqeust in the request_queue
         * @param request request entry to push
         */
        void push_request(request_entry &request);

        /** get the front of the bottom queue
         * @return bottom entry
         */
        bottom_entry top_bottom();

        /** get the front of the bottom queue and pop
         * @return bottom entry
         */
        bottom_entry pop_bottom();
        request_entry pop_request();
        bool done();
        bool bottom_queue_empty();
        void send_request(request_entry &request);

        /** handler to manage a generic Message
         * @param msg Message
         * @param request corresponding reqeust entry
         */
        void handle_reply(recon::Message* msg,request_entry &request);
        std::vector<Message*> get_flush_queue();
        void clean_queue();

        /** toggle flush on off
         * @param new_state new flushing state
         */
        void toggle_flush(bool new_state);
        int bottom_queue_size();
        int request_queue_size();
        bool is_flushing();
        std::vector<NTL::ZZ_p> elements();
};
}
}
#endif //RECON_PEER_H
