#ifndef UNPACKER_UNPACKER_H
#define UNPACKER_UNPACKER_H


#include <Key.h>
#include <Packets/Packet.h>
#include "DBManager.h"
#include "DBStruct.h"
#include <boost/program_options.hpp>
#include <functional>
#include <Misc/radix64.h>
#include <syslog.h>
#include <future>
#include <iostream>
#include <cstring>
#include <random>
#include <climits>
#include "../common/Thread_Pool.h"
#include <thread>

namespace po = boost::program_options;

namespace Unpacker {

	int unpacker(po::variables_map &vm);
    void unpack_key_th(std::shared_ptr<UNPACKER_DBManager> dbm, const std::vector<OpenPGP::Key::Ptr> &pks);
    void unpack_key(const OpenPGP::Key::Ptr &key, std::shared_ptr<UNPACKER_DBManager> &dbm);
    UNPACKER_DBStruct::signatures get_signature_data(const OpenPGP::Key::SigPairs::iterator &sp, const OpenPGP::Packet::Key::Ptr &priKey);
    UNPACKER_DBStruct::pubkey get_publicKey_data(const OpenPGP::Packet::Tag::Ptr &p, const OpenPGP::Packet::Key::Ptr &priKey);
    UNPACKER_DBStruct::userID get_userID_data(const OpenPGP::Packet::Tag::Ptr &user_pkt, const OpenPGP::Packet::Key::Ptr &key);
    void get_userAttributes_data(const OpenPGP::Packet::Tag::Ptr &p, UNPACKER_DBStruct::userAtt &ua_struct);

    void get_tag2_subpackets_data(const std::vector<OpenPGP::Subpacket::Tag2::Sub::Ptr> &subps, UNPACKER_DBStruct::signatures *ss);

    void handle_wrong_sig(UNPACKER_DBStruct::signatures &ss, const OpenPGP::Packet::Key::Ptr &key, const OpenPGP::Packet::User::Ptr &user,
                          const OpenPGP::Packet::Tag2::Ptr &sig);
    void handle_wrong_sig(UNPACKER_DBStruct::signatures &ss, const OpenPGP::Packet::Key::Ptr &key, const OpenPGP::Packet::Key::Ptr &subkey,
                          const OpenPGP::Packet::Tag2::Ptr &sig);
};

#endif //UNPACKER_UNPACKER_H
