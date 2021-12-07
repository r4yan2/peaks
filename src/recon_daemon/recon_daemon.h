#ifndef RECON_DAEMON_H
#define RECON_DAEMON_H

#include <boost/program_options.hpp>
#include "peer.h"

namespace po = boost::program_options;

namespace peaks{
namespace recon{

void build(po::variables_map &vm);
class Recon{
    private:
        std::unique_ptr<Peer> peer;
        int server, client;
    public:
        Recon(po::variables_map &vm);
        void run();
};

}
}
#endif
