#ifndef RECON_PEER_H
#define RECON_PEER_H
#include "Recon_settings.h"
#include "Utils.h"
#include <random>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include <NTL/matrix.h>
#include "PTree_settings.h"
#include "Connection_Manager.h"
#include "pTreeDB.h"
#include "exception.h"
#include <cmath>
#include <NTL/mat_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ_pXFactoring.h>
#include <algorithm>
#include <boost/bind.hpp>
#include <boost/coroutine/coroutine.hpp>

using namespace Recon_settings;

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
    std::vector<Message> messages;
};

class Peer{
    private:
        /** this will hold the Connection Manager singleton */
        Connection_Manager cn;
        Ptree tree;
    public:
        /** constructor take the pair (hostname, port) which identify the host */
        Peer(peertype peer);

        peertype choose_partner();
        void client_recon(Peer_config remote_config, Connection_Manager cn);
        void gossip();
        void start_recon();
        Communication request_poly_handler(ReconRequestPoly* req);
        Communication request_full_handler(ReconRequestFull* req);
        std::pair<Vec<ZZ_p>,Vec<ZZ_p>> solve(Vec<ZZ_p> r_samples, int r_size, Vec<ZZ_p> l_samples, int l_size, Vec<ZZ_p> points);

};

#endif //RECON_PEER_H 
