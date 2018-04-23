#ifndef UNPACKER_UNPACKER_H
#define UNPACKER_UNPACKER_H


#include <Key.h>
#include <Packets/Packet.h>
#include "DBManager.h"
#include "DBStruct.h"


namespace Unpacker {

    void unpack_key_th(const std::vector<OpenPGP::PublicKey::Ptr> &pks);
    void unpack_key(const OpenPGP::PublicKey::Ptr &key, const std::shared_ptr<DBManager> &dbm);
    DBStruct::signatures get_signature_data(const OpenPGP::Key::SigPairs::iterator &sp, const OpenPGP::Packet::Key::Ptr &priKey);
    DBStruct::pubkey get_publicKey_data(const OpenPGP::Packet::Tag::Ptr &p, const OpenPGP::Packet::Key::Ptr &priKey);
    void get_userAttributes_data(const OpenPGP::Packet::Tag::Ptr &p, DBStruct::userAtt &ua_struct);

    void get_tag2_subpackets_data(const std::vector<OpenPGP::Subpacket::Tag2::Sub::Ptr> &subps, DBStruct::signatures *ss);

    void handle_wrong_sig(DBStruct::signatures &ss, const OpenPGP::Packet::Key::Ptr &key, const OpenPGP::Packet::User::Ptr &user,
                          const OpenPGP::Packet::Tag2::Ptr &sig);
    void handle_wrong_sig(DBStruct::signatures &ss, const OpenPGP::Packet::Key::Ptr &key, const OpenPGP::Packet::Key::Ptr &subkey,
                          const OpenPGP::Packet::Tag2::Ptr &sig);
};

#endif //UNPACKER_UNPACKER_H
