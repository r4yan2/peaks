#ifndef RECON_SETTINGS_H
#define RECON_SETTINGS_H
#include<string>

namespace Recon_settings{
    const int mbar = 5;
    const int bq = 2; //bitquantum
    const int max_ptree_nodes = 1000;
    const int ptree_thresh_mult = 10;
    const int num_samples = mbar + 1;
    const int split_threshold = ptree_thresh_mult * mbar;
    const int join_threshold = split_threshold/2;
    const std::string P_SKS_STRING = "530512889551602322505127520352579437339";
    const int sks_zp_bytes = 17; /**< #Bytes of P_SKS */
    const int hashquery_len = 16;
    const int reconciliation_timeout = 45;
    const std::string peaks_version = "1.1.6";
    const int peaks_recon_port = 11372;
    const int peaks_http_port = 11373;
    const std::string peaks_filters = "yminsky.dedup,yminsky.merge";
    const std::string name = "peaks_recon";
    const std::string http_addr = ":" + std::to_string(peaks_http_port);
    const std::string recon_addr = ":" + std::to_string(peaks_recon_port);
    const int gossip_interval = 60;
    const int max_outstanding_recon_req = 100;
    const static int max_read_len = 1 << 24;
    const static int max_recover_size = 15000;
    const static unsigned int default_timeout = 300;
    const static int max_request_queue_len = 60000;
    const static int request_chunk_size = 100;
}
#endif
