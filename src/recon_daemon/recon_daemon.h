#ifndef RECON_DAEMON_H
#define RECON_DAEMON_H

#include <boost/program_options.hpp>
#include "peer.h"

namespace po = boost::program_options;

namespace peaks{
namespace recon{

void build();
void build_slow();
void recon();
}
}
#endif
