#include "unpacker.h"
#include "common/DBStruct.h"
#include <common/config.h>
#include <common/utils.h>

using namespace std;
using namespace OpenPGP;
using namespace peaks::common;

namespace peaks{
namespace import{
namespace Import {

    std::vector<std::string> unpack_string_th(std::shared_ptr<IMPORT_DBManager> & dbm, const vector<string> keys){
        std::vector<std::string> hashes;
        for (auto key_str : keys){
            Key::Ptr key;
            std::size_t pos = 0;
            try{
                key = std::make_shared<Key>();
                key->read_raw(key_str, pos, true);
                key->set_type(PGP::PUBLIC_KEY_BLOCK);
            }catch (exception &e){
                syslog(LOG_WARNING, "Key not unpacked due to not meaningfulness (%s).", e.what());
                continue;
            }catch (error_code &ec){
                syslog(LOG_WARNING, "Key not unpacked due to not meaningfulness (%s).", ec.message().c_str());
                continue;
            }
            DBStruct::gpg_keyserver_data gpg_keyserver_table;
            std::tuple<std::string, int> res = dbm->store_certificate_to_filestore(key->raw());
            read_gpg_keyserver_data(key, &gpg_keyserver_table, std::get<0>(res), std::get<1>(res), key_str.size());
            hashes.push_back(gpg_keyserver_table.hash);
            //dbm->write_gpg_keyserver_csv(gpg_keyserver_table);
            dbm->write_gpg_keyserver_table(gpg_keyserver_table);
        }
        return hashes;
    }

    void unpack_dump_th(std::shared_ptr<IMPORT_DBManager> & dbm, const vector<std::string> &files, const bool &fast){
        for (const auto &f : files) {
            try{
                std::cout << "----------------------- " << f << " -----------------------" << std::endl;
                ifstream file(f, ios::in | ios::binary);
                if (file.is_open()){
                    file.seekg(0, std::ios::end);
                    size_t size = file.tellg();
                    std::string buffer(size, ' ');
                    file.seekg(0);
                    file.read(&buffer[0], size); 

                    std::string::size_type pos = 0;
                    bool end = false;
                    int idx = 0;
                    while(!end){
                        idx++;
                        Key::Ptr key = std::make_shared<Key>();
                        std::string::size_type start = pos;
                        try{
                            key->read_raw(buffer, pos, true);
                            key->set_type(PGP::PUBLIC_KEY_BLOCK);
                        }catch (exception &e){
                            syslog(LOG_WARNING, "Key not unpacked due to not meaningfulness (%s). Index: %d. Packet: %lu", e.what(), idx, key->get_packets().size());

                            //dbm->write_broken_key_csv(file, e.what());
                            end = true;
                        }catch (ParsingErrc &ec){
                            if ((ec == ParsingErrc::EndOfStream) || pos >= size){
                                end = true;
                            } else {
                                syslog(LOG_WARNING, "Key not unpacked due to not meaningfulness (ErrorCode: %d). Index: %d. Packet: %lu", ec, idx, key->get_packets().size());
                                //dbm->write_broken_key_csv(file, ec.message());
                            }
                        }catch (KeyErrc &ke) {
                            if (pos >= size){
                                end = true;
                            } else {
                                syslog(LOG_WARNING, "Catched KeyError (ErrorCode: %d). Index: %d", ke, idx);
                            }
                        }
                        if (pos >= size)
                            end = true;
                        DBStruct::gpg_keyserver_data gpg_keyserver_table;
                        read_gpg_keyserver_data(key, &gpg_keyserver_table, f, start, pos-start);
                        dbm->write_gpg_keyserver_csv(gpg_keyserver_table);
                    }
                }else{
                    throw std::runtime_error("Unable to open file: " + f);
                }
                file.close();
            }catch(exception &e){
                syslog(LOG_CRIT, "Unable to open file: %s -  (%s).", f.c_str(), e.what());
                cerr << "Unable to open file: " << f << " (" << e.what() << ")." << endl;
                continue;
            }
        }
    }
    
    void read_gpg_keyserver_data(const OpenPGP::Key::Ptr &k, DBStruct::gpg_keyserver_data *gk, const std::string filename, const int pos, const int len) {
        gk->fingerprint = k->fingerprint();
        gk->version = k->version();
        gk->ID = mpitodec(rawtompi(k->keyid()));
        gk->hash = Utils::calculate_hash(k);
        gk->filename = filename;
        gk->origin = pos;
        gk->len = len;
    }

}
}
}
