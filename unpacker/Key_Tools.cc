#include <sys/syslog.h>
#include "Key_Tools.h"

using namespace OpenPGP;
using namespace std;

namespace Key_Tools {
    Key::pkey readPkey(const Key::Ptr &k, UNPACKER_DBStruct::Unpacker_errors &modified){
        set<int> possibleSigTypes {0x10, 0x11, 0x12, 0x13, 0x30, 0x18, 0x19, 0x1F, 0x20, 0x28};
        Key::pkey pk;
        pk.key = nullptr;
        PGP::Packets ps = k->get_packets();
        Packet::Tag::Ptr lastPacket = nullptr;
        Packet::Tag::Ptr lastUser = nullptr;
        for (auto &p: ps){
            switch (p->get_tag()){
                case Packet::PUBLIC_KEY:
                    pk.key = p;
                case Packet::PUBLIC_SUBKEY:
                    lastPacket = p;
                    break;
                case Packet::SIGNATURE: {
                    if (lastPacket == nullptr){
                        pk.trashPackets.push_back(p);
                        modified.modified = true;
                        modified.comments.emplace_back(
                                "Signature Packet found without any other packet before. Signature Packet will not be unpacked");
                        continue;
                        // throw runtime_error("Cannot reconstruct pkey from invalid key, lastPacket is NULL");
                    }
                    if (possibleSigTypes.find(dynamic_pointer_cast<Packet::Tag2>(p)->get_type()) == possibleSigTypes.end()){
                        pk.trashPackets.push_back(p);
                        modified.modified = true;
                        modified.comments.emplace_back(
                                "Not-a-key-Signature Packet found, it will not be unpacked: " + Signature_Type::NAME.at(dynamic_pointer_cast<Packet::Tag2>(p)->get_type()));
                        continue;
                    }
                    switch (lastPacket->get_tag()){
                        case Packet::PUBLIC_KEY:
                            pk.keySigs.insert(make_pair(lastPacket, p));
                            break;
                        case Packet::PUBLIC_SUBKEY:
                            pk.subKeys.insert(make_pair(lastPacket, p));
                            break;
                        case Packet::USER_ATTRIBUTE:
                        case Packet::USER_ID:
                            pk.uids.insert(make_pair(lastPacket, p));
                            break;
                        default:
                            pk.trashPackets.push_back(p);
                            modified.modified = true;
                            modified.comments.push_back("Cannot reconstruct pkey from invalid key, "
                                 "lastPacket is of type " + Packet::NAME.at(lastPacket->get_tag()) +
                                 ", NOT RECOGNIZED!");
                            throw logic_error("Cannot reconstruct pkey from invalid key");
                    }
                    break;
                }
                case Packet::USER_ATTRIBUTE:
                    if (lastUser == nullptr){
                        pk.trashPackets.push_back(p);
                        modified.modified = true;
                        modified.comments.emplace_back(
                                "User Attribute Packet found without a UserID. UA Packet will not be unpacked");
                        continue;
                        //throw std::runtime_error("User attribute found without a UserID packet");
                    }
                    pk.uid_userAtt.insert(std::make_pair(lastUser, p));
                    lastPacket = p;
                    break;
                case Packet::USER_ID:
                    pk.uid_list.push_back(p);
                    lastUser = p;
                    lastPacket = p;
                    break;
                default:
                    pk.trashPackets.push_back(p);
                    modified.modified = true;
                    modified.comments.push_back("Not valid packet found: " + Packet::NAME.at(p->get_tag()));
                    break;
            }
        }
        return pk;
    }

    void makePKMeaningful(Key::pkey &pk, UNPACKER_DBStruct::Unpacker_errors &modified){
        Key::pkey new_pk;
        set<int> uid_sigTypes {0x10, 0x11, 0x12, 0x13, 0x30};
        set<int> key_sigTypes {0x18, 0x19, 0x1F, 0x20, 0x28};
        if (pk.key == nullptr){ // There must be the primary key
            throw runtime_error(Packet::NAME.at(Packet::PUBLIC_KEY) + " not found");
        }
        new_pk.key = pk.key;

        for (auto &keySig : pk.keySigs) {
            if (keySig.first->get_tag() == Packet::PUBLIC_KEY && keySig.second->get_tag() == Packet::SIGNATURE){
                Packet::Tag2::Ptr sig = dynamic_pointer_cast<Packet::Tag2>(keySig.second);
                if (key_sigTypes.find(sig->get_type()) != key_sigTypes.end()){
                    new_pk.keySigs.insert(keySig);
                }else {
                    modified.modified = true;
                    modified.comments.push_back("Second packet of pk.keySigs mapping contains a not valid signature: " +
                                   Signature_Type::NAME.at(sig->get_type()));
                }
            }else {
                modified.modified = true;
                modified.comments.emplace_back("pk.keySigs mapping contains a wrong packet");
            }
        }

        for (auto &uid : pk.uids) {
            if ((uid.first->get_tag() == Packet::USER_ID || uid.first->get_tag() == Packet::USER_ATTRIBUTE) &&
                uid.second->get_tag() == Packet::SIGNATURE){
                Packet::Tag2::Ptr sig = dynamic_pointer_cast<Packet::Tag2>(uid.second);
                if (uid_sigTypes.find(sig->get_type()) != uid_sigTypes.end()){
                    new_pk.uids.insert(uid);
                }else {
                    modified.modified = true;
                    modified.comments.push_back("Second packet of pk.uids mapping contains a not valid signature: " +
                                       Signature_Type::NAME.at(sig->get_type()));
                }
            }else {
                modified.modified = true;
                modified.comments.emplace_back("pk.uids mapping contains a wrong packet");
            }
        }

        for (auto &subKey : pk.subKeys) {
            if (subKey.first->get_tag() == Packet::PUBLIC_SUBKEY && subKey.second->get_tag() == Packet::SIGNATURE){
                Packet::Tag2::Ptr sig = dynamic_pointer_cast<Packet::Tag2>(subKey.second);
                if (key_sigTypes.find(sig->get_type()) != key_sigTypes.end()){
                    new_pk.subKeys.insert(subKey);
                }else{
                    modified.modified = true;
                    modified.comments.push_back("Second packet of pk.subKeys mapping contains a not valid signature: " +
                                       Signature_Type::NAME.at(sig->get_type()));
                }
            }else {
                modified.modified = true;
                modified.comments.emplace_back("pk.subKeys mapping contains a wrong packet");
            }

        }

        for (const auto &uid_att : pk.uid_userAtt) {
            if(uid_att.first->get_tag() != Packet::USER_ID){
                throw runtime_error("Left packet (of pk.uid_userAtt mapping) is not a UserID");
            }
            if(uid_att.second->get_tag() != Packet::USER_ATTRIBUTE){
                throw runtime_error("Right packet (of pk.uid_userAtt mapping) is not a UserAttribute");
            }
            new_pk.uid_userAtt.insert(uid_att);
        }

        new_pk.uid_list = pk.uid_list;
        new_pk.trashPackets = pk.trashPackets;

        pk = new_pk;
    }
}
