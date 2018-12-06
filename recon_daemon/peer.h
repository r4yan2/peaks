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
#include <queue>
#include <curl/curl.h>
#include <dump_import.h>
#include <unistd.h>
#include <chrono>


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
    zset elements;
    /** flag to mark if queued messages has to be send */
    bool send;
    /** status of the current message exchange */
    Communication_status status;
    /** Messages generated from the current message exchange */
    std::vector<Message*> messages;
    /** Default constructor for this struct, set send to false and communication status to None */
    Communication():send(false), status(Communication_status::NONE){}
};

struct request_entry{
    pnode_ptr node;
    bitset key;
};

namespace recon_state{
enum recon_state: int {Bottom=0, FlushEnded=1};
}

struct bottom_entry{
    request_entry request;
    uint8_t state;
};

/**Peer class represent a peer during recon.
 * This class hold all the main code needed
 * for recon.
 */
class Peer{
    private:
        /** hold the Connection Manager reference*/
        Connection_Manager cn;
        /** hold the ptree reference */
        Ptree tree;
        /** hold the list of peers specified in membership file */
        std::vector<peertype> membership;
    public:
        /** 
         * constructor take a ptree on which operate
         * @param new_tree Init with the reference to the curren ptree
         */ 
        Peer(Ptree &new_tree);

        /** choose random peer partner among the
         * one specified in membership
         */
        peertype choose_partner();

        /** start recon daemon processes */
        void start();

        /** start only server recon */
        void start_server();

        /** start only client recon */
        void start_client();

        /** 
         * @param Choosen peer from membership file
         * recon as client with choosen peer
         */
        void client_recon(const peertype&);

        void gossip(); /**< recon as client */

        void serve(); /**< recon as server */

        /**
         * Manage interaction with the client during recon
         * @param remote_peer peer client
         */
        void interact_with_client(peertype &remote_peer);

        /** 
         * fetch the given element from the peer 
         * @param peer peer from which to fetch elements
         * @param elems elements to recover
         */
        void fetch_elements(const peertype &peer, const std::vector<NTL::ZZ_p> &elems);

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

        /** implementation of linear interpolation
         * @param r_samples remote samples
         * @param r_size size of remote samples vector
         * @param l_samples local samples
         * @param l_size size of local samples vector
         * @param points default interpolation points
         * @return a pair of elements vectors which holds the respectively missing elements
         */
        std::pair<std::vector<NTL::ZZ_p>,std::vector<NTL::ZZ_p>> solve(const std::vector<NTL::ZZ_p> &r_samples, const int r_size, const std::vector<NTL::ZZ_p> &l_samples, const int l_size, const std::vector<NTL::ZZ_p> &points);

        /** method used to request a chunk of data from the other peer
         * @param peer peer to send requests to
         * @param elemnts elements to request
         * @return vector which contains the requested elements
         */
        std::vector<std::string> request_chunk(const peertype &peer, const std::vector<NTL::ZZ_p> &elements);

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
        zset remote_set;

        /** used to know when to flush pending messages */
        bool flushing=false;

        /** vector keeps current pending messages */
        std::vector<Message*> messages;

        /** reference to connection manager */
        Connection_Manager cn;

    public:
        /** recon manager is initialized with a reference to the current connection manager 
         * @param conn_manager reference to initialized connection manage
         */
        Recon_manager(Connection_Manager &conn_manager);
        ~Recon_manager();

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
        void handle_reply(Message* msg,request_entry &request);
        void flush_queue();

        /** toggle flush on off
         * @param new_state new flushing state
         */
        void toggle_flush(bool new_state);
        int bottom_queue_size();
        int request_queue_size();
        bool is_flushing();
        std::vector<NTL::ZZ_p> elements();
};

#endif //RECON_PEER_H
