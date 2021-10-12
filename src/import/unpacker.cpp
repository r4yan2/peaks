#include "unpacker.h"
#include <common/config.h>

using namespace std;
using namespace OpenPGP;
using namespace peaks::common;

namespace peaks{
namespace import{
namespace Import {

    std::vector<std::string> unpack_string_th(std::shared_ptr<IMPORT_DBManager> & dbm, const vector<string> keys){
        std::vector<std::string> hashes;
        for (auto key_str : keys){
            try{
                Key::Ptr key;
                key = std::make_shared<Key>(key_str);
                fast_unpack(key, dbm);
                hashes.push_back(calculate_hash(key));
            }catch (exception &e){
                syslog(LOG_WARNING, "Key not unpacked due to not meaningfulness (%s).", e.what());
                cerr << "Key not unpacked due to not meaningfulness (" << e.what() << ")." << endl;
                continue;
            }catch (error_code &ec){
                syslog(LOG_WARNING, "Key not unpacked due to not meaningfulness (%s).", ec.message().c_str());
                cerr << "Key not unpacked due to not meaningfulness (" << ec.message() << ")." << endl;
                continue;
            }
        }
    }

    void insert_csv(std::shared_ptr<IMPORT_DBManager> & dbm_, const std::string &filename, int selection){
        std::cout << "Working on " << filename << std::endl;
        dbm_->lockTables(selection);
        dbm_->insertCSV(filename, selection);
        dbm_->unlockTables();
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
                    while(!end){
                        try{
                            Key::Ptr key = std::make_shared<Key>();
                            key->read_raw(buffer, pos, fast);
                            fast_unpack(key, dbm);
                            if (pos >= size)
                                end = true;
                            if (Context::context().quitting) return;
                        }catch (exception &e){
                            syslog(LOG_WARNING, "Key not unpacked due to not meaningfulness (%s).", e.what());
                            cerr << "Key not unpacked due to not meaningfulness (" << e.what() << ")." << endl;
                            cerr << "Need to discard the rest of the file" << std::endl;

                            //dbm->write_broken_key_csv(file, e.what());
                            end = true;
                        }catch (ParsingErrc &ec){
                            if ((ec == ParsingErrc::EndOfStream) || pos >= size){
                                cerr << "End of dump, data read: " << pos << std::endl;
                                end = true;
                            } else {
                                //syslog(LOG_WARNING, "Key not unpacked due to not meaningfulness (%s).", ec.message().c_str());
                                cerr << "Key not unpacked due to not meaningfulness (" << ec << ")." << endl;
                                //dbm->write_broken_key_csv(file, ec.message());
                            }
                        }catch (KeyErrc &ke) {
                            if (pos >= size){
                                cerr << "End of dump, data read: " << pos*100/size << std::endl;
                                end = true;
                            } else {
                                cerr << "catched KeyError" << ke << " current pos "<< (pos/size)*100.0 << "%" << std::endl;
                            }
                        }
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

    void fast_unpack(Key::Ptr &key, const shared_ptr<IMPORT_DBManager> &dbm){
        DBStruct::gpg_keyserver_data gpg_keyserver_table;
        key->set_type(PGP::PUBLIC_KEY_BLOCK);
        read_gpg_keyserver_data(key, &gpg_keyserver_table);
        dbm->write_gpg_keyserver_csv(gpg_keyserver_table, 0);
    }

    void read_gpg_keyserver_data(const Key::Ptr &k, DBStruct::gpg_keyserver_data *gk){
        gk->fingerprint = k->fingerprint();
        gk->version = k->version();
        gk->ID = mpitodec(rawtompi(k->keyid()));
        gk->certificate = k->raw();
        gk->hash = calculate_hash(k);
    }

    std::string calculate_hash(const Key::Ptr &k){
        std::string concatenation = concat(get_ordered_packet(k->get_packets()));
        return hexlify(Hash::use(Hash::ID::MD5, concatenation), true);
    }

    PGP::Packets get_ordered_packet(PGP::Packets packet_list){
        sort(packet_list.begin(), packet_list.end(), compare);
        return packet_list;
    }

    bool compare(const Packet::Tag::Ptr &p1, const Packet::Tag::Ptr &p2){
        if (p1->get_tag() == p2->get_tag()){
            return p1->raw() < p2->raw();
        }else{
            return p1->get_tag() < p2->get_tag();
        }
    }

    string concat(const PGP::Packets &packet_list){
        string out = "";
        for (const auto &p: packet_list){
            out += unhexlify(makehex(p->get_tag(), 8));
            out += unhexlify(makehex(p->raw().size(), 8));
            out += p->raw();
        }

        return out;
    }

}
}
}
