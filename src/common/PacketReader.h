#ifndef PKS_PACKETREADER_H
#define PKS_PACKETREADER_H

#include <Key.h>
#include "db.h"

namespace peaks {
namespace common{
namespace pr {
    void readPublicKeyPacket(const std::string &arm, std::shared_ptr<DBManager> dbm, bool ptree_override=false, bool unpack=true, bool armored=true);
    bool manageMerge(OpenPGP::Key::Ptr key, const std::string & content);

    void read_gpg_keyserver_data(const OpenPGP::Key::Ptr &k, gpg_keyserver_data *gk);
    userID read_userID_data(const OpenPGP::Key::Ptr &k, const OpenPGP::Packet::Tag13::Ptr &u);

    std::string get_ascii_arm(const std::string &armor_key);

    OpenPGP::PGP::Packets get_ordered_packet(OpenPGP::PGP::Packets packet_list);
    std::string concat(const OpenPGP::PGP::Packets &packet_list);

    bool compare(const OpenPGP::Packet::Tag::Ptr &p1, const OpenPGP::Packet::Tag::Ptr &p2);
}

}
}
#endif //PKS_PACKETREADER_H
