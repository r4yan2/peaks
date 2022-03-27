#include <PGP.h>
#include "PacketReader.h"
#include "encoder.h"
#include <istream>
#include <sys/syslog.h>
#include <common/errors.h>
#include <regex>
#include <thread>
#include "db.h"
#include <recon_daemon/pTreeDB.h>


using namespace std;
using namespace OpenPGP;

namespace peaks {
namespace pks{

void pr::readPublicKeyPacket(const string &arm, peaks::pks::CGI_DBManager *dbm){
    PublicKey::Ptr key(new PublicKey(arm));

    gpg_keyserver_data gk = {};
    vector<userID> uids;
    bool exist = false;

    cout << "Reading data..." << endl;

    try{
        for (const auto &p: key->get_packets()){
            if (p->get_tag() == Packet::PUBLIC_KEY){
                // Verifico se la chiave è già presente nel DB ed eventualmente mergio
                string q = hexlify(dynamic_pointer_cast<Packet::Tag6>(p)->get_fingerprint());
                std::string query = dbm -> fingerprintQuery(q);
                if(query != ""){ exist = pr::manageMerge(key, query); }
                break;
            }
        }
        key->meaningful();

        thread fullfill_gpg_ks (read_gpg_keyserver_data, key, &gk);
        gk.error_code = 0;
        for(auto &p: key->get_packets()){
            if(p->get_tag() == Packet::USER_ID){
                uids.push_back(read_userID_data(key, dynamic_pointer_cast<Packet::Tag13>(p)));
            }
        }
        fullfill_gpg_ks.join();
    }catch(error_code &ec){
        switch (ec.value()){
            case static_cast<int>(KeyErrc::NotExistingVersion):
                throw std::runtime_error("Error: PGP Packet doesn't have a valid version number");
            case static_cast<int>(KeyErrc::BadKey):
                syslog(LOG_WARNING, "Submitted a PGP packet of type: %d", key->get_type());
                throw ec;
            case static_cast<int>(KeyErrc::NotAPublicKey):
                syslog(LOG_WARNING, "Submitted a private key!");
                throw ec;
            case static_cast<int>(KeyErrc::NotEnoughPackets): {
                PGP::Packets ps = key->get_packets();
                if (ps.empty()) {
                    throw std::runtime_error("No packets found inside the key");
                } else if (ps[0]->get_tag() != Packet::PUBLIC_KEY) {
                    throw std::runtime_error("No primary key packet found");
                } else {
                    read_gpg_keyserver_data(key, &gk);
                    gk.error_code = ec.value();
                }
                break;
            }
            case static_cast<int>(KeyErrc::FirstPacketWrong):{
                bool found = false;
                Key::Packets p_list = key->get_packets();
                for (auto pk = p_list.begin(); pk != p_list.end(); pk++){
                    if ((*pk)->get_tag() == Packet::PUBLIC_KEY){
                        Packet::Tag::Ptr tempPacket = *pk;
                        p_list.erase(pk);
                        p_list.insert(p_list.begin(), tempPacket);
                        key->set_packets(p_list);
                        found = true;
                        break;
                    }
                }
                if (!found){
                    throw std::runtime_error("No primary key packet found");
                }
            }
            case static_cast<int>(KeyErrc::SignAfterPrimary):
            case static_cast<int>(KeyErrc::AtLeastOneUID):
            case static_cast<int>(KeyErrc::WrongSignature):
            case static_cast<int>(KeyErrc::NoSubkeyFound):
            case static_cast<int>(KeyErrc::Ver3Subkey):
            case static_cast<int>(KeyErrc::NoSubkeyBinding):
            case static_cast<int>(KeyErrc::NotAllPacketsAnalyzed): {
                thread fullfill_gpg_ks(read_gpg_keyserver_data, key, &gk);
                gk.error_code = ec.value();

                for(auto &p: key->get_packets()){
                    if(p->get_tag() == Packet::USER_ID){
                        uids.push_back(read_userID_data(key, dynamic_pointer_cast<Packet::Tag13>(p)));
                    }
                }
                fullfill_gpg_ks.join();
                break;
            }
            case static_cast<int>(ParsingErrc::LengthLEQZero):
            case static_cast<int>(ParsingErrc::PubkeyAlgorithmNotFound):
            case static_cast<int>(ParsingErrc::PubkeyVersionNotFound):
            case static_cast<int>(ParsingErrc::ParsingError):
            case static_cast<int>(ParsingErrc::SignaturePKANotFound):
            case static_cast<int>(ParsingErrc::SignatureHashNotFound):
            case static_cast<int>(ParsingErrc::SignatureVersionNotFound):
            case static_cast<int>(ParsingErrc::SignatureLengthWrong):
                throw std::runtime_error("Cannot parse armored: " + ec.message());
            default:
                throw std::logic_error("Exception not managed");
        }
    }

    cout << "Submitting data" << endl;
    dbm->insert_gpg_keyserver(gk);
    peaks::recon::Ptree().insert(gk.hash);
    //if (exist) {
    //    dbm->update_gpg_keyserver(gk);
    //} else {
    //    dbm->insert_gpg_keyserver(gk);
    //}

    for (auto &uid: uids){
        dbm->insert_user_id(uid);
    }
    cout << "Upload of the key finished" << endl;
}

bool pr::manageMerge(PublicKey::Ptr key, const std::string & content){
    cout << "Key already in the database, proceeding with merge" << endl;
    const Key::Ptr oldKey = make_shared<Key>(content);
    try{
        key->merge(oldKey);
    }catch (error_code &ec){
        if (ec.value() == static_cast<int>(KeyErrc::DifferentKeys)){
            syslog(LOG_ERR, "Tried merge between two different keys");
            return false;
        }else{
            syslog(LOG_ERR, "Not recognized error code during merge");
            throw logic_error("Not recognized error code during merge");
        }
    }
    return true;
}

void pr::read_gpg_keyserver_data(const Key::Ptr &k, gpg_keyserver_data *gk){
    gk->fingerprint = k->fingerprint();
    gk->version = k->version();
    gk->ID = mpitodec(rawtompi(k->keyid()));
    gk->certificate = k->raw();
    gk->hash = hexlify(Hash::use(Hash::ID::MD5, concat(get_ordered_packet(k->get_packets()))), true);
}

PGP::Packets pr::get_ordered_packet(PGP::Packets packet_list){
    sort(packet_list.begin(), packet_list.end(), compare);
    return packet_list;
}

bool pr::compare(const Packet::Tag::Ptr &p1, const Packet::Tag::Ptr &p2){
    if (p1->get_tag() == p2->get_tag()){
        return p1->raw() < p2->raw();
    }else{
        return p1->get_tag() < p2->get_tag();
    }
}

string pr::concat(const PGP::Packets &packet_list){
    string out = "";
    for (const auto &p: packet_list){
        out += unhexlify(makehex(p->get_tag(), 8));
        out += unhexlify(makehex(p->raw().size(), 8));
        out += p->raw();
    }
    return out;
}

userID pr::read_userID_data(const Key::Ptr &k, const Packet::Tag13::Ptr &u){
    std::regex mail_regex(
            "(?:(?:[^<>()\\[\\].,;:\\s@\"]+(?:\\.[^<>()\\[\\].,;:\\s@\"]+)*)|\".+\")@(?:(?:[^<>()‌​\\[\\].,;:\\s@\"]+\\.)+[^<>()\\[\\].,;:\\s@\"]{2,})");
    // get Email
    string user = u->get_contents();
    string email = "";
    std::cmatch match;

    if (user.size() < 5000 && std::regex_search(user.c_str(), match, mail_regex)){
        email = string(match[0].first + 1, match[0].first + strlen(match[0].first) - 1);
    }
    userID uid{
            .ownerkeyID = mpitodec(rawtompi(k->keyid())),
            .fingerprint = k->fingerprint(),
            .name = ascii2radix64(u->get_contents()),
            .email = ascii2radix64(email)
    };
    return uid;
}

string pr::get_ascii_arm(const std::string &armor_key) {
    //Key::Type_t type = 0;
    istringstream stream(armor_key);
    std::string line;
    while (std::getline(stream, line) && line.substr(0, 15) != "-----BEGIN PGP ");
    /*if (("-----BEGIN PGP " + PGP::ASCII_Armor_Header[2] + "-----") != line){
        syslog(LOG_WARNING, "Submitted a PGP packet of type: %d", PGP::ASCII_Armor_Header[type]);
        throw error_code(KeyErrc::BadKey);
    }*/
    // read Armor Key(s)
    while (std::getline(stream, line) && !line.empty());
    // read up to tail
    std::string body;
    while (std::getline(stream, line) && (line.substr(0, 13) != "-----END PGP ")){
        body += line;
    }
    // check for a checksum
    if (body[body.size() - 5] == '='){
        body = radix642ascii(body.substr(0, body.size() - 5));
    }
    else{
        body = radix642ascii(body);
    }
    return body;
}
}
}
