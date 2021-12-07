#ifndef _PEAKS_GENERIC_CONFIG
#define _PEAKS_GENERIC_CONFIG

#include <atomic>
#include <boost/program_options.hpp>
#include <boost/program_options/variables_map.hpp>
#include "DBManager.h"
#include <string>
#include <vector>
#include <NTL/ZZ_p.h>

namespace po = boost::program_options;

namespace peaks{
  
  namespace settings{
  
  struct DBSettings{
      std::string db_user;
      std::string db_password;
      std::string db_host;
      int db_port;
      std::string db_database;
      std::string tmp_folder;
      std::string error_folder;
      std::string filestorage_format;
      int filestorage_maxsize;
      int expire_interval;
  };
  
  struct Ptree_config{
      /** mbar is a parameter which influence the ptree and all the syncronization
       * process*/
      int mbar;
  
      /** the bitquantum influence how many child a node have in the prefix tree */
      int bq;
  
      /** the maximum amount of nodes in a ptree */
      int max_ptree_nodes;
  
      /** a r-value to be multiplies with other to obtain a specific threshold */
      int ptree_thresh_mult;
  
      /** number of samples used in the linear interpolation algorithm */
      int num_samples;
  
      /** points a #num_samples points which are used to perform linear interpolation */
      std::vector<NTL::ZZ_p> points;
  
      /** threshold at which a node is saturated by elements and needs to be splitted into 2^bq child nodes */
      int split_threshold;
  
      /** threshold at which a node is no longer necessary to exists and it's joine with the parent */
      int join_threshold;
      
      /** flag to indicate the bitstring notation in use */
      int sks_bitstring;
  };
  
  struct Recon_config{
  
      /** path to the membership file, used to know who are the peers for the syncronization */
      std::string membership_config;
  
      /** port used for the recon protocol */
      int peaks_recon_port;
  
      /** maximum chunk of key that can be requested by the peer */
      int request_chunk_size;
  
      /** if dry run is set recon daemon will only fetch certificates without importing them */
      unsigned long dry_run;
  
      /** flag used to ignore logging for known bugs */
      int ignore_known_bug;
  
      /** sks_zp_bytes + 1 */
      int hashquery_len;
  
      int max_outstanding_recon_req;
  
      /** interval between gossip attemps */
      int gossip_interval;
  
      /** maximum number of elements recoverable from a single reconing session */
      int max_recover_size;
  };
  
  struct Connection_config{
      /** version of peaks */
      std::string peaks_version;
  
      /** port used to serve certificates */
      int peaks_http_port;
  
      /** filters used for certificate merging */
      std::string peaks_filters;
  
      /** maximum bytes length of a single message */
      int max_read_len;
  
      /** asyncronous request timeout in sec */
      int async_timeout_sec;
  
      /** asyncronous request timeout in micro sec */
      int async_timeout_usec;
  };
  
  struct Message_config{
      
      /** current finite field choosen by sks */
      std::string P_SKS_STRING;
      /** number of bytes which composes the P_SKS representation */
      int sks_zp_bytes;
      /** max length for the recon request queue */
      int max_request_queue_len;
  };
  
  }

    class Context {
        public:
	        po::variables_map vm;
            settings::DBSettings dbsettings;
            settings::Ptree_config treesettings;
            settings::Connection_config connsettings;
            settings::Message_config msgsettings;
            settings::Recon_config peersettings;
            std::atomic<bool> critical_section;
            static Context& context();
            Context(Context const &) = delete;
            void operator=(Context const &) = delete;
            void setContext(const po::variables_map &);
            int filestorage_index;
            NTL::ZZ P_SKS;
        private:
            Context(){}
    };
}

#define CONTEXT Context::context()
#endif
