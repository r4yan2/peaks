#ifndef IMPORT_UNPACKER_H
#define IMPORT_UNPACKER_H


#include <Key.h>
#include <Packets/Packet.h>
#include <bits/shared_ptr.h>
#include "DBManager.h"
#include "DBStruct.h"
#include <ctime>
#include <Packets/packets.h>
#include <Misc/mpi.h>
#include <sys/syslog.h>
#include <Misc/sigcalc.h>
#include <common/errors.h>
#include <thread>
#include <cmath>
#include "Key_Tools.h"
#include <boost/program_options.hpp>
#include <stdio.h>
#include <dirent.h>

namespace po = boost::program_options;
using namespace OpenPGP;

namespace Import {

    void Import(po::variables_map &vm);
    void unpack_string_th(const Import_DBConfig &db_config, const std::vector<std::string> keys);
    void unpack_dump_th(const Import_DBConfig &db_config, const std::vector<std::string> &files, const bool &fast);
    void unpack_dump(std::ifstream &key_file, const std::shared_ptr<IMPORT_DBManager> &dbm);
    void unpack_string(std::string key, const std::shared_ptr<IMPORT_DBManager> &dbm);
    void fast_unpack(Key::Ptr &key, const std::shared_ptr<IMPORT_DBManager> &dbm);
    void unpack(Key::Ptr &key, const std::shared_ptr<IMPORT_DBManager> &dbm);
    IMPORT_DBStruct::signatures get_signature_data(const OpenPGP::Key::SigPairs::iterator &sp, const OpenPGP::Packet::Key::Ptr &priKey, const std::string &uatt_id = "");
    IMPORT_DBStruct::pubkey get_publicKey_data(const OpenPGP::Packet::Tag::Ptr &p, const OpenPGP::Packet::Key::Ptr &priKey);
    IMPORT_DBStruct::userID get_userID_data(const OpenPGP::Packet::Tag::Ptr &user_pkt, const OpenPGP::Packet::Key::Ptr &key);
    void get_userAttributes_data(const OpenPGP::Packet::Tag::Ptr &p, IMPORT_DBStruct::userAtt &ua_struct);
    void read_gpg_keyserver_data(const OpenPGP::Key::Ptr &k, IMPORT_DBStruct::gpg_keyserver_data *gk);
    void get_tag2_subpackets_data(const std::vector<OpenPGP::Subpacket::Tag2::Sub::Ptr> &subps, IMPORT_DBStruct::signatures *ss);

    void handle_wrong_sig(IMPORT_DBStruct::signatures &ss, const OpenPGP::Packet::Key::Ptr &key, const OpenPGP::Packet::User::Ptr &user,
                          const OpenPGP::Packet::Tag2::Ptr &sig);
    void handle_wrong_sig(IMPORT_DBStruct::signatures &ss, const OpenPGP::Packet::Key::Ptr &key, const OpenPGP::Packet::Key::Ptr &subkey,
                          const OpenPGP::Packet::Tag2::Ptr &sig);


    OpenPGP::PGP::Packets get_ordered_packet(OpenPGP::PGP::Packets packet_list);
    std::string concat(const OpenPGP::PGP::Packets &packet_list);
    bool compare(const OpenPGP::Packet::Tag::Ptr &p1, const OpenPGP::Packet::Tag::Ptr &p2);


};

#endif //IMPORT_UNPACKER_H
