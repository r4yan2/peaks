#ifndef RECON_DAEMON_H
#define RECON_DAEMON_H

#include <boost/program_options.hpp>
#include <NTL/ZZ_p.h>
#include "Utils.h"
#include "DBManager.h"
#include "peer.h"
#include "pTreeDB.h"
#include "logger.h"
#include <sys/syslog.h>
#include "../dump_import/Config.h"

namespace po = boost::program_options;
void build(po::variables_map &vm);
void recon(po::variables_map &vm);
/** calculate Zpoints for the current number of samples */
std::vector<NTL::ZZ_p> Zpoints(int num_samples);

#endif
