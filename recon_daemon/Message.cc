#include "Message.h"


void ReconRequestPoly::marshal(buftype &buf){
 
    buf.write_bitset(prefix);
    buf.write_int(size);
    buf.write_zz_array(samples);
}

void ReconRequestPoly::unmarshal(sbuftype buf){
     g_logger.log(Logger_level::DEBUG, "unpacking reconrequestpoly");
     prefix = buf.read_bitset();
     size = buf.read_int();
     samples = buf.read_zz_array();

     //DEBUG
     std::string test;
     to_string(prefix, test);
     g_logger.log(Logger_level::DEBUG, "prefix: " + test + " size: " + std::to_string(size));
}

void ReconRequestFull::marshal(buftype &buf){
    buf.write_bitset(prefix);
    buf.write_zset(samples);
}

void ReconRequestFull::unmarshal(sbuftype buf){
    prefix = buf.read_bitset();
    samples = buf.read_zset();
}

void Elements::marshal(buftype &buf){
    buf.write_zset(samples);
}

void Elements::unmarshal(sbuftype buf){
    samples = buf.read_zset();
}

void FullElements::marshal(buftype &buf){
    buf.write_zset(samples);
}

void FullElements::unmarshal(sbuftype buf){
    samples = buf.read_zset();
}

void SyncFail::marshal(buftype &buf){}

void SyncFail::unmarshal(sbuftype buf){}

void Done::marshal(buftype &buf){}

void Done::unmarshal(sbuftype buf){}

void Flush::marshal(buftype &buf){}

void Flush::unmarshal(sbuftype buf){}

void ErrorType::marshal(buftype &buf){
    buf.write_string(text);
}

void ErrorType::unmarshal(sbuftype buf){
    text = buf.read_string();
}

void DBRequest::marshal(buftype &buf){
    buf.write_string(text);
}

void DBRequest::unmarshal(sbuftype buf){
    text = buf.read_string();
}

void DBReply::marshal(buftype &buf){
    buf.write_string(text);
}

void DBReply::unmarshal(sbuftype buf){
    text = buf.read_string();
}

void Peer_config::marshal(buftype &buf){
    /*
     * 5 is the number of field into Peer_config
     * + length of other
     */
    buf.write_int(5 + other.size());
    buf.write_string("version");
    buf.write_string(version);
    buf.write_string("http port");
    buf.write_int(4);
    buf.write_int(http_port);
    buf.write_string("bitquantum");
    buf.write_int(4);
    buf.write_int(bq);
    buf.write_string("mbar");
    buf.write_int(4);
    buf.write_int(mbar);
    buf.write_string("filters");
    buf.write_string(filters);
    if (not (other.empty())){
        for (auto kv: other){
            buf.write_string(kv.first);
            buf.write_string(kv.second);
        }
    }
}

void Peer_config::unmarshal(sbuftype buf){
     std::string key;
     std::uint32_t val;
     std::string value;
     std::uint32_t a = buf.read_int(true);
     for (uint32_t i=0; i<a; i++){
         key = buf.read_string();
         if ((key == "http port") ||
            (key == "bitquantum") ||
            (key == "mbar")) {
            val = buf.read_int(true);
            if (val != 4) g_logger.log(Logger_level::WARNING, "Invalid len size!");
            val = buf.read_int();
            }
         else value = buf.read_string();
         if (key == "version") version = value;
         else if (key == "http port") http_port = val;
         else if (key == "bitquantum") bq = val;
         else if (key == "mbar") mbar = val;
         else if (key == "filters") filters = value;
         else other[key] = value;
               }
}

void Config_mismatch::marshal(buftype &buf){
    buf.write_string(failed);
    buf.write_string(reason);
}

void Config_ok::marshal(buftype &buf){
    buf.write_string(passed);
}


