#ifndef RECON_SETTINGS_H
#define RECON_SETTINGS_H
#include <string>

struct Configtype{
    int mbar;
    int bq;
    int max_ptree_nodes;
    int ptree_thresh_mult;
    int num_samples;
    int split_threshold;
    int join_threshold;
    std::string P_SKS_STRING;
    int sks_zp_bytes;
    int hashquery_len;
    int reconciliation_timeout;
    std::string peaks_version;
    int peaks_recon_port;
    int peaks_http_port;
    std::string peaks_filters;
    std::string name;
    int gossip_interval;
    int max_read_len;
    int max_read_len_shift;
    int max_recover_size;
    int default_timeout;
    int max_request_queue_len;
    int request_chunk_size;
    int max_outstanding_recon_req;
    int sks_compliant;
};

extern Configtype recon_settings;

#endif
