#ifndef UNPACKER_UNPACKER_H
#define UNPACKER_UNPACKER_H

#include <common/config.h>
#include <Key.h>
#include <Packets/Packet.h>
#include "DBManager.h"
#include <functional>
#include <Misc/radix64.h>
#include <syslog.h>
#include <future>
#include <iostream>
#include <cstring>
#include <random>
#include <climits>
#include <common/Thread_Pool.h>
#include <thread>

using namespace peaks::settings;

namespace peaks{
namespace unpacker{
class Unpacker{
    public:
	    Unpacker();
        void run();
        void store_keymaterial(const std::shared_ptr<UNPACKER_DBManager> &dbm);
    private:
        int nThreads, key_per_thread, limit;
};

// static functions
void unpack();
void unpack_key_th(const std::shared_ptr<UNPACKER_DBManager> &dbm, const std::shared_ptr<DBResult> &, size_t, size_t);
void unpack_key(const OpenPGP::Key::Ptr &key, std::shared_ptr<UNPACKER_DBManager> &dbm);
DBStruct::signatures get_signature_data(const OpenPGP::Key::SigPairs::iterator &sp, const OpenPGP::Packet::Key::Ptr &priKey, const std::string &uatt_id="");
DBStruct::pubkey get_publicKey_data(const OpenPGP::Packet::Tag::Ptr &p, const OpenPGP::Packet::Key::Ptr &priKey);
DBStruct::userID get_userID_data(const OpenPGP::Packet::Tag::Ptr &user_pkt, const OpenPGP::Packet::Key::Ptr &key);
void get_userAttributes_data(const OpenPGP::Packet::Tag::Ptr &p, DBStruct::userAtt &ua_struct);

void get_tag2_subpackets_data(const std::vector<OpenPGP::Subpacket::Tag2::Sub::Ptr> &subps, DBStruct::signatures *ss);

void handle_wrong_sig(DBStruct::signatures &ss, const OpenPGP::Packet::Key::Ptr &key, const OpenPGP::Packet::User::Ptr &user,
                      const OpenPGP::Packet::Tag2::Ptr &sig);
void handle_wrong_sig(DBStruct::signatures &ss, const OpenPGP::Packet::Key::Ptr &key, const OpenPGP::Packet::Key::Ptr &subkey,
                  const OpenPGP::Packet::Tag2::Ptr &sig);

}
}
#endif //UNPACKER_UNPACKER_H
