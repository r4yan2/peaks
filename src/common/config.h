#ifndef _PEAKS_GENERIC_CONFIG
#define _PEAKS_GENERIC_CONFIG

#include <atomic>
#include <boost/program_options.hpp>
#include <boost/program_options/positional_options.hpp>
#include <boost/program_options/variables_map.hpp>
#include "DBManager.h"
#include <string>
#include <vector>
#include <NTL/ZZ_p.h>

namespace po = boost::program_options;
typedef std::vector<std::tuple<std::string, std::string, int>> membership_t;

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
      size_t filestorage_maxsize;
      int expire_interval;
  };
  
  struct Ptree_config{
      /** mbar is a parameter which influence the ptree and all the syncronization
       * process*/
      int mbar;
  
      /** the bitquantum influence how many child a node have in the prefix tree */
      int bq;
  
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
  };
  
  struct Recon_config{
  
      /** port used for the recon protocol */
      int peaks_recon_port;
  
      /** maximum chunk of key that can be requested by the peer */
      int request_chunk_size;
  
      /** sks_zp_bytes - 1 */
      long hashquery_len;
  
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
      size_t max_read_len;
  
      /** asyncronous request timeout in sec */
      int async_timeout_sec;
  
      /** asyncronous request timeout in micro sec */
      int async_timeout_usec;
  };
  
  struct Message_config{
      
      /** current finite field choosen by sks */
      std::string P_SKS_STRING;
      /** number of bytes which composes the P_SKS representation */
      long sks_zp_bytes;
      /** max length for the recon request queue */
      size_t max_request_queue_len;
  };
  
  }

    class Context {
        public:
	        po::variables_map vm;
            po::options_description 
                internal_config,
                generic_config,
                db_config,
                folder_config,
                global,
                dump_desc,
                import_desc,
                unpack_desc,
                analyzer_desc,
                recon_desc,
                build_desc,
                cgi_desc,
                blocklist_desc
                ;
            po::positional_options_description
                blocklist_positional
                ;
            settings::DBSettings dbsettings;
            settings::Ptree_config treesettings;
            settings::Connection_config connsettings;
            settings::Message_config msgsettings;
            settings::Recon_config peersettings;
            bool critical_section;
            static Context& context();
            Context(Context const &) = delete;
            void operator=(Context const &) = delete;
            void setContext(const po::variables_map &);
            int filestorage_index;
            NTL::ZZ P_SKS;
            std::string init_options(int argc, char* argv[]);
            void parse_config(std::istream& conf, po::variables_map &vm);
            void write_config();
            bool has(const std::string &name);
            void set(const std::string &name, const boost::any &value);
            template <typename T> T get(const std::string &name, T def = T()){
                auto it = vm.find(name);
                if (it != vm.end()){
                    try{
                        return (*it).second.as<T>();
                    }catch(...){
                        std::cerr << "Failed cast of " << name << " to " << typeid(def).name() << std::endl;
                    }
                }
                return def;
            }
        private:
            Context();
    };
}

#define CONTEXT Context::context()
#endif
