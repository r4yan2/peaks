#include <ctime>
#include <Packets/packets.h>
#include <Misc/mpi.h>
#include <Misc/sigcalc.h>
#include <common/errors.h>
#include <cmath>
#include <regex>
#include <Misc/PKCS1.h>
#include "unpacker.h"
#include "Key_Tools.h"


using namespace std;
using namespace OpenPGP;

namespace Unpacker {

    int unpacker(po::variables_map &vm){
        int log_option;
        int log_upto;

        if (vm.count("stdout")){
            std::cout << "logging to stdout" << std::endl;
            log_option = LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID;
        }
        else{
            log_option = LOG_PID;
        }
        if (vm.count("debug")){
            std::cout << "debug output" << std::endl;
            log_upto = LOG_UPTO(LOG_DEBUG);
        }
        else{
            log_upto = LOG_UPTO(LOG_INFO); 
        }

        openlog("pgp_unpacker", log_option, LOG_USER);
        setlogmask(log_upto);
        syslog(LOG_NOTICE, "Unpacker daemon is starting up!");
    
        unsigned int nThreads = std::thread::hardware_concurrency() / 2 + 1;
        unsigned int key_per_thread;
        unsigned int limit = vm["max_unpacker_limit"].as<unsigned int>();
    
        if(vm.count("threads"))
            nThreads = vm["threads"].as<unsigned int>();
        
        syslog(LOG_NOTICE, "Using %d Threads", nThreads);
    
        if(vm.count("limit"))
            limit = vm["limit"].as<unsigned int>();

        std::cout << "limiting analysis at " << limit << " keys" << std::endl;
    
        if(vm.count("keys"))
            key_per_thread = vm["keys"].as<unsigned int>();
        else
            key_per_thread = 1 + ((limit - 1)/nThreads); 
     
        if(UNPACKER_Utils::create_folders(vm["unpacker_tmp_folder"].as<std::string>()) == -1){
            syslog(LOG_WARNING,  "Unable to create temp folder");
            exit(-1);
        }
    
        if (UNPACKER_Utils::create_folders(vm["unpacker_error_folder"].as<std::string>()) == -1){
            syslog(LOG_WARNING,  "Unable to create temp folder");
            exit(-1);
        }
        const Unpacker_DBConfig db_settings = {
            vm["db_host"].as<std::string>(),
            vm["db_user"].as<std::string>(),
            vm["db_password"].as<std::string>(),
            vm["db_database"].as<std::string>(),
            vm["unpacker_tmp_folder"].as<std::string>(),
            vm["unpacker_error_folder"].as<std::string>(),
        };

        std::shared_ptr<UNPACKER_DBManager> dbm = std::make_shared<UNPACKER_DBManager>(db_settings);
        dbm->init_database_connection();
    
        std::vector<UNPACKER_DBStruct::gpg_keyserver_data> gpg_data = dbm->get_certificates(limit);
        
        std::shared_ptr<Thread_Pool> pool = std::make_shared<Thread_Pool>();
        std::vector<std::thread> pool_vect(nThreads);
    
        for (unsigned int i = 0; i < nThreads; i++){
            pool_vect[i] = std::thread([=] { pool->Infinite_loop_function(); });
        }
    
        for (unsigned int i = 0; i < gpg_data.size();){
            std::vector<Key::Ptr> pks;
            for (unsigned int j = 0; i < gpg_data.size() && j < key_per_thread; j++, i++){
                try{
                    //std::stringstream s(gpg_data[i].certificate);
                    //PGP::Ptr pkt(new PGP(s)), true));
                    //PGP::Ptr pkt(new PGP(gpg_data[i].certificate));
                    //pkt -> set_type(PGP::PUBLIC_KEY_BLOCK);
                    //pks.push_back(std::make_shared<PublicKey>(PublicKey(*pkt)));
                    Key::Ptr key = std::make_shared<Key>(gpg_data[i].certificate);
                    key->set_type(PGP::PUBLIC_KEY_BLOCK);
                    pks.push_back(key);
                }catch (std::exception &e){
                    dbm->set_as_not_analyzable(gpg_data[i].version, gpg_data[i].fingerprint, "Error during creation of the object PGP::Key");
                    syslog(LOG_CRIT, "Error during creation of the object PGP::Key - %s", e.what());
                    continue;
                }catch (std::error_code &e){
                    dbm->set_as_not_analyzable(gpg_data[i].version, gpg_data[i].fingerprint, "Error during creation of the object PGP::Key");
                    syslog(LOG_CRIT, "Error during creation of the object PGP::Key - %s", e.message().c_str());
                    continue;
                }catch (...){
                    syslog(LOG_CRIT, "Error during creation of the object PGP::Key");
                    continue;
                }
            }
            pool->Add_Job([=] { return Unpacker::unpack_key_th(db_settings, pks); });
        }
    
        pool->Stop_Filling_UP();
    
        for (auto &th: pool_vect){
            while (!th.joinable()){}
            th.join();
        }
    
        dbm->insertCSV(UNPACKER_Utils::get_files(db_settings.unpacker_tmp_folder, UNPACKER_Utils::PUBKEY), UNPACKER_Utils::PUBKEY);
        dbm->insertCSV(UNPACKER_Utils::get_files(db_settings.unpacker_tmp_folder, UNPACKER_Utils::USERID), UNPACKER_Utils::USERID);
        dbm->insertCSV(UNPACKER_Utils::get_files(db_settings.unpacker_tmp_folder, UNPACKER_Utils::USER_ATTRIBUTES), UNPACKER_Utils::USER_ATTRIBUTES);
        dbm->insertCSV(UNPACKER_Utils::get_files(db_settings.unpacker_tmp_folder, UNPACKER_Utils::SIGNATURE), UNPACKER_Utils::SIGNATURE);
        dbm->insertCSV(UNPACKER_Utils::get_files(db_settings.unpacker_tmp_folder, UNPACKER_Utils::SELF_SIGNATURE), UNPACKER_Utils::SELF_SIGNATURE);
        dbm->insertCSV(UNPACKER_Utils::get_files(db_settings.unpacker_tmp_folder, UNPACKER_Utils::UNPACKED), UNPACKER_Utils::UNPACKED);
        dbm->insertCSV(UNPACKER_Utils::get_files(db_settings.unpacker_tmp_folder, UNPACKER_Utils::UNPACKER_ERRORS), UNPACKER_Utils::UNPACKER_ERRORS);
        dbm->UpdateSignatureIssuingFingerprint(limit);
        dbm->UpdateSignatureIssuingUsername();
        dbm->UpdateIsExpired();
        dbm->UpdateIsRevoked();
        dbm->UpdateIsValid();
    
        syslog(LOG_NOTICE, "Unpacker daemon is stopping!");
        return 0;
    }

    void unpack_key_th(const Unpacker_DBConfig &db_settings, const vector<Key::Ptr> &pks){
        
        std::shared_ptr<UNPACKER_DBManager> dbm = std::make_shared<UNPACKER_DBManager>(db_settings);
        dbm->init_database_connection();
        dbm->openCSVFiles();

        for (const auto &pk : pks) {
            try{
                unpack_key(pk, dbm);
            }catch(exception &e) {
                syslog(LOG_WARNING, "Key not analyzed due to not meaningfulness (%s). is_analyzed will be set equals to -1", e.what());
                cout << "Key not analyzed due to not meaningfulness (" << e.what() << "). is_analyzed will be set equals to -1" << endl;
                dbm->set_as_not_analyzable(pk->version(), pk->fingerprint(), e.what());
                continue;
            }catch (error_code &ec){
                syslog(LOG_WARNING, "Key not unpacked due to not meaningfulness (%s).", ec.message().c_str());
                cerr << "Key not unpacked due to not meaningfulness (" << ec.message() << ")." << endl;
                dbm->set_as_not_analyzable(pk->version(), pk->fingerprint(), ec.message());
                continue;
            }catch (...){
                syslog(LOG_CRIT, "Error during creation of the object PGP::Key");
                continue;
            }
        }
    }

    void unpack_key( const Key::Ptr &key, const shared_ptr<UNPACKER_DBManager> &dbm){

        Key::pkey pk;
        UNPACKER_DBStruct::Unpacker_errors modified;

        try{
            modified.version = key->version();
            modified.fingerprint = key->fingerprint();
            key->meaningful();
            pk = key->get_pkey();
            Key_Tools::makePKMeaningful(pk, modified);
        }catch (error_code &ec){
            switch (ec.value()) {
                case static_cast<int>(KeyErrc::NotExistingVersion):
                case static_cast<int>(KeyErrc::BadKey):
                case static_cast<int>(KeyErrc::NotAPublicKey):
                case static_cast<int>(KeyErrc::NotASecretKey):
                    throw runtime_error("Not unpackable key: " + ec.message());
                case static_cast<int>(KeyErrc::NotEnoughPackets): {
                    if (key->get_packets().empty()) {
                        throw std::runtime_error("No packets found inside the key");
                    }
                }
                case static_cast<int>(KeyErrc::FirstPacketWrong):
                case static_cast<int>(KeyErrc::SignAfterPrimary):
                case static_cast<int>(KeyErrc::AtLeastOneUID):
                case static_cast<int>(KeyErrc::WrongSignature):
                case static_cast<int>(KeyErrc::NoSubkeyFound):
                case static_cast<int>(KeyErrc::Ver3Subkey):
                case static_cast<int>(KeyErrc::NoSubkeyBinding):
                case static_cast<int>(KeyErrc::NotAllPacketsAnalyzed):
                    pk = Key_Tools::readPkey(key, modified);
                    Key_Tools::makePKMeaningful(pk, modified);
                    break;
                default:
                    throw runtime_error("Not unpackable key: " + ec.message());
            }

        }

        Packet::Key::Ptr primaryKey = static_pointer_cast<Packet::Key>(pk.key);
        vector<UNPACKER_DBStruct::pubkey> unpackedPubkeys;
        vector<UNPACKER_DBStruct::userID> unpackedUserID;
        vector<UNPACKER_DBStruct::userAtt> unpackedUserAttributes;
        vector<UNPACKER_DBStruct::signatures> unpackedSignatures; // contains also self-signatures

        try{
            unpackedPubkeys.push_back(get_publicKey_data(primaryKey, primaryKey));
        }catch (exception &e){
            modified.modified = true;
            modified.comments.push_back("Unpacking jumped due to: " + string(e.what()));
        }

        for (auto i = pk.keySigs.begin(); i != pk.keySigs.end(); i++){
            try{
                unpackedSignatures.push_back(get_signature_data(i, primaryKey));
            }catch (exception &e){
                modified.modified = true;
                modified.comments.push_back("Unpacking jumped due to: " + string(e.what()));
            }
        }

        for (const auto &u: pk.uid_list){
            try {
                unpackedUserID.push_back(get_userID_data(u, primaryKey));
            }catch (exception &e){
                modified.modified = true;
                modified.comments.push_back("Unpacking jumped due to: " + string(e.what()));
            }
        }

        for (auto i = pk.uids.begin(); i != pk.uids.end(); i++){
            try{
                string uatt_id = "";
                if (i->first->get_tag() == Packet::USER_ATTRIBUTE){
                    uatt_id = to_string(std::distance(pk.uid_userAtt.begin(), pk.uid_userAtt.find(i->first)));
                }
                unpackedSignatures.push_back(get_signature_data(i, primaryKey));
            }catch (exception &e){
                modified.modified = true;
                modified.comments.push_back("Unpacking jumped due to: " + string(e.what()));
            }
        }

        for (auto it = pk.uid_userAtt.begin(); it != pk.uid_userAtt.end(); it++) {
            try {
                UNPACKER_DBStruct::userAtt ua_struct{
                        .id = std::distance(pk.uid_userAtt.begin(), it) + 1,
                        .fingerprint = primaryKey->get_fingerprint(),
                        .name = ascii2radix64(dynamic_pointer_cast<Packet::Tag13>(it->first)->get_contents())
                };
                get_userAttributes_data(it->second, ua_struct);
                unpackedUserAttributes.push_back(ua_struct);
            }catch (exception &e){
                modified.modified = true;
                modified.comments.push_back("Unpacking jumped due to: " + string(e.what()));
            }
        }

        for (auto i = pk.subKeys.begin(); i != pk.subKeys.end(); i = pk.subKeys.upper_bound(i->first)){
            try{
                unpackedPubkeys.push_back(get_publicKey_data(i->first, primaryKey));
            }catch (exception &e){
                modified.modified = true;
                modified.comments.push_back("Unpacking jumped due to: " + string(e.what()));
            }

            auto range_sub = pk.subKeys.equal_range(i->first);
            assert(range_sub.second == pk.subKeys.upper_bound(i->first));
            for (auto j = range_sub.first; j != range_sub.second; j++){
                try{
                    unpackedSignatures.push_back(get_signature_data(j, primaryKey));
                }catch (exception &e){
                    modified.modified = true;
                    modified.comments.push_back("Unpacking jumped due to: " + string(e.what()));
                }
            }
        }

        // Insert in DB

        for (auto &p: unpackedPubkeys){
            for (auto &s: unpackedSignatures){
                if (s.signedFingerprint == p.fingerprint && !s.keyExpirationTime.empty()){
                    p.expirationTime = s.keyExpirationTime;
                }
                if (s.issuingKeyId == p.keyId){
                    s.issuingFingerprint = p.fingerprint;
                }
            }
            dbm->write_pubkey_csv(p);
        }
        for (auto &u: unpackedUserID){
            dbm->write_userID_csv(u);
        }
        for (auto &u: unpackedUserAttributes){
            dbm->write_userAttributes_csv(u);
        }
        for (auto it = unpackedSignatures.begin(); it != unpackedSignatures.end(); it++){
            if(!dbm->existSignature(*it) || find(it + 1, unpackedSignatures.end(), *it) == unpackedSignatures.end()) {
                dbm->write_signature_csv(*it);
                if (it->issuingKeyId == it->signedKeyId && !it->signedUsername.empty()){
                    dbm->write_self_signature_csv(*it);
                }
            }
        }

        dbm->write_unpackerErrors_csv(modified);
        dbm->write_unpacked_csv(key, modified);
    }

    UNPACKER_DBStruct::signatures get_signature_data(const Key::SigPairs::iterator &sp, const Packet::Key::Ptr &priKey) {
        UNPACKER_DBStruct::signatures ss;
        Packet::Tag2::Ptr sig = dynamic_pointer_cast<Packet::Tag2>(sp->second);

        ss.type = sig->get_type();
        ss.pubAlgorithm = sig->get_pka();
        ss.hashAlgorithm = sig->get_hash();
        ss.version = sig->get_version();
        ss.hashHeader = sig->get_left16();

        if (Packet::is_user(sp->first->get_tag())){
            Packet::User::Ptr user = dynamic_pointer_cast<Packet::User>(sp->first);
            ss.signedKeyId = mpitodec(rawtompi(priKey->get_keyid()));
            ss.signedFingerprint = priKey->get_fingerprint();
            if (user->get_tag() == Packet::USER_ID){
                Packet::Tag13::Ptr u = dynamic_pointer_cast<Packet::Tag13>(user);
                ss.signedUsername = ascii2radix64(u -> get_contents());
            }/*else{
                ss.signedUsername = ascii2radix64("User Attribute");
            }*/

            switch(sig->get_type()) {
                case Signature_Type::GENERIC_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
                    ss.trustLevel = 0;
                    ss.signedHash = to_sign_10(priKey, user, sig);
                    break;
                case Signature_Type::PERSONA_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
                    ss.trustLevel = 1;
                    ss.signedHash = to_sign_11(priKey, user, sig);
                    break;
                case Signature_Type::CASUAL_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
                    ss.trustLevel = 2;
                    ss.signedHash = to_sign_12(priKey, user, sig);
                    break;
                case Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET:
                    ss.trustLevel = 3;
                    ss.signedHash = to_sign_13(priKey, user, sig);
                    break;
                case Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE:
                    ss.signedHash = to_sign_30(priKey, user, sig);
                    ss.isRevocation = 1;
                    break;
                default:
                    break;
            }

            if (ss.hashHeader != ss.signedHash.substr(0, 2)){
                handle_wrong_sig(ss, priKey, user, sig);
            }
            if (ss.hashHeader != ss.signedHash.substr(0, 2)){
                ss.hashMismatch = 1;
            }
        }else if(Packet::is_key_packet(sp->first->get_tag())){
            Packet::Key::Ptr k = dynamic_pointer_cast<Packet::Key>(sp->first);
            ss.signedKeyId = mpitodec(rawtompi(k->get_keyid()));
            ss.signedFingerprint = k->get_fingerprint();

            switch(sig->get_type()) {
                case Signature_Type::SUBKEY_BINDING_SIGNATURE:
                    ss.signedHash = to_sign_18(priKey, k, sig);
                    break;
                case Signature_Type::PRIMARY_KEY_BINDING_SIGNATURE:
                    ss.signedHash = to_sign_19(priKey, k, sig);
                    break;
                case Signature_Type::SIGNATURE_DIRECTLY_ON_A_KEY:
                    ss.signedHash = to_sign_1f(k, sig);
                    break;
                case Signature_Type::KEY_REVOCATION_SIGNATURE:
                    ss.signedHash = to_sign_20(k, sig);
                    ss.isRevocation = 1;
                    break;
                case Signature_Type::SUBKEY_REVOCATION_SIGNATURE:
                    ss.signedHash = to_sign_28(k, sig);
                    ss.isRevocation = 1;
                    break;
                default:
                    break;
            }
            if (ss.hashHeader != ss.signedHash.substr(0, 2)){
                handle_wrong_sig(ss, priKey, k, sig);
            }
            if (ss.hashHeader != ss.signedHash.substr(0, 2)){
                ss.hashMismatch = 1;
            }
        }

        ss.creationTime = show_time_format(sig->get_times()[0], "%F %T", 80);
        ss.issuingKeyId = mpitodec(rawtompi(sig->get_keyid()));
        if (ss.version == 4) {
            if (sig->get_times()[1] != 0){
                ss.expirationTime = show_time_format(sig->get_times()[1], "%F %T", 80);
            }
            if (sig->get_times()[2] != 0){
                ss.keyExpirationTime = show_time_format(sig->get_times()[2], "%F %T", 80);
            }

            vector<Subpacket::Tag2::Sub::Ptr> hashed_subpackets = sig->get_hashed_subpackets();
            vector<Subpacket::Tag2::Sub::Ptr> unhashed_subpackets = sig->get_unhashed_subpackets();
            get_tag2_subpackets_data(hashed_subpackets, &ss);
            get_tag2_subpackets_data(unhashed_subpackets, &ss);
        }

        PKA::Values algValues = sig->get_mpi();
        switch (ss.pubAlgorithm){
            case PKA::ID::RSA_SIGN_ONLY:
            case PKA::ID::RSA_ENCRYPT_OR_SIGN:
                if (algValues.size() > 0) 
                    ss.s = mpitoraw(algValues[0]);
                break;
            case PKA::ID::DSA:
            case PKA::ID::ECDSA:
            case PKA::ID::EdDSA:
                if (algValues.size() > 1){
                    ss.r = mpitoraw(algValues[0]);
                    ss.s = mpitoraw(algValues[1]);
                }
                break;
            default:
                syslog(LOG_ERR, "Not valid/implemented algorithm found: %i", ss.hashAlgorithm);
                break;
        }

        return ss;
    }

    void handle_wrong_sig(UNPACKER_DBStruct::signatures &ss, const Packet::Key::Ptr &key, const Packet::Key::Ptr &subkey,
                          const Packet::Tag2::Ptr &sig){
        vector<string> prob_hash;
        prob_hash.push_back(to_sign_18(key, subkey, sig));
        prob_hash.push_back(to_sign_18(key, key, sig));
        prob_hash.push_back(to_sign_18(subkey, key, sig));
        prob_hash.push_back(to_sign_18(subkey, subkey, sig));

        prob_hash.push_back(to_sign_19(key, subkey, sig));
        prob_hash.push_back(to_sign_19(key, key, sig));
        prob_hash.push_back(to_sign_19(subkey, key, sig));
        prob_hash.push_back(to_sign_19(subkey, subkey, sig));

        prob_hash.push_back(to_sign_1f(key, sig));
        prob_hash.push_back(to_sign_1f(subkey, sig));

        prob_hash.push_back(to_sign_20(key, sig));
        prob_hash.push_back(to_sign_20(subkey, sig));

        prob_hash.push_back(to_sign_28(key, sig));
        prob_hash.push_back(to_sign_28(subkey, sig));
        for (const auto &h: prob_hash){
            if (ss.hashHeader == h.substr(0,2)){
                ss.signedHash = h;
            }
        }
    }

    void handle_wrong_sig(UNPACKER_DBStruct::signatures &ss, const Packet::Key::Ptr &key, const Packet::User::Ptr &user,
                          const Packet::Tag2::Ptr &sig) {
        if (user->get_tag() == Packet::USER_ID){
            return;
        }
        Packet::Tag17::Attributes a_list = dynamic_pointer_cast<Packet::Tag17>(user)->get_attributes();
        for (unsigned int i = 0; i < 3; i++){
            string pkt = "";
            for (const auto &a: a_list){
                string data = std::string(1, a->get_type() | (a->get_critical()?0x80:0x00)) + a->raw();
                if (i == 0){
                    pkt += std::string(1, data.size()) + data;
                }else if (i == 1){
                    pkt += unhexlify(makehex(((((data.size() >> 8) + 192) << 8) + (data.size() & 0xff) - 192), 4))
                           + data;
                }else{
                    pkt += "\xff" + unhexlify(makehex(data.size(), 8)) + data;
                }
            }
            string cert = overkey(key);
            if (sig->get_version() == 3 || sig->get_version() == 2){
                cert += pkt;
            }
            else if (sig->get_version() == 4){
                cert += "\xd1" + unhexlify(makehex(pkt.size(), 8)) + pkt;
            }

            string tmp_signedHash = Hash::use(sig -> get_hash(), addtrailer(cert, sig));
            if (ss.hashHeader == tmp_signedHash.substr(0,2) || i > 1){
                ss.signedHash = tmp_signedHash;
                return;
            }
        }
    }

    UNPACKER_DBStruct::pubkey get_publicKey_data(const Packet::Tag::Ptr &p, const Packet::Key::Ptr &priKey) {
        Packet::Key::Ptr k = dynamic_pointer_cast<Packet::Key>(p);
        UNPACKER_DBStruct::pubkey pk;

        pk.keyId = mpitodec(rawtompi(k->get_keyid()));

        pk.version = k->get_version();
        pk.fingerprint = k->get_fingerprint();
        if (p->get_tag() == Packet::PUBLIC_SUBKEY) {
            pk.priFingerprint = priKey -> get_fingerprint();
        }else{
            pk.priFingerprint = k->get_fingerprint();
        }
        pk.pubAlgorithm = k->get_pka();
        pk.creationTime = show_time_format(k->get_time(), "%F %T", 80);

        if(k->get_version() < 4) {
            try{
                unsigned long t = k->get_exp_time();
                if (t != 0){
                    pk.expirationTime = show_time_format(k->get_time() + (t * 86400), "%F %T", 80);
                }
            }catch (runtime_error &e){
                pk.expirationTime = "";
            }
        }

        PKA::Values algValues = k->get_mpi();

        if (pk.version < 4 && algValues.size() > 1) {
            pk.algValue.at(0) = mpitoraw(algValues[1]);
            pk.algValue.at(1) = mpitoraw(algValues[0]);
        } else {
            switch (pk.pubAlgorithm) {
                case PKA::ID::RSA_ENCRYPT_ONLY:
                case PKA::ID::RSA_ENCRYPT_OR_SIGN:
                case PKA::ID::RSA_SIGN_ONLY:
                    if (algValues.size() > 1){
                        pk.algValue.at(0) = mpitoraw(algValues[1]);
                        pk.algValue.at(1) = mpitoraw(algValues[0]);
                    }
                    break;
                case PKA::ID::ELGAMAL:
                    if (algValues.size() > 2){
                        pk.algValue.at(2) = mpitoraw(algValues[0]);
                        pk.algValue.at(4) = mpitoraw(algValues[1]);
                        pk.algValue.at(5) = mpitoraw(algValues[2]);
                    }
                    break;
                case PKA::ID::DSA:
                    if (algValues.size() > 3){
                        pk.algValue.at(2) = mpitoraw(algValues[0]);
                        pk.algValue.at(3) = mpitoraw(algValues[1]);
                        pk.algValue.at(4) = mpitoraw(algValues[2]);
                        pk.algValue.at(5) = mpitoraw(algValues[3]);
                    }
                    break;
                case PKA::ID::ECDSA:
                case PKA::ID::EdDSA:
                case PKA::ID::ECDH:
                    if (algValues.size() > 1){
                        pk.algValue.at(2) = mpitoraw(algValues[0]);
                        pk.curve = hexlify(k->get_curve());
                    }
                    break;
                default:
                    syslog(LOG_WARNING, "Algorithm type (%i) for pubkey not found.", pk.pubAlgorithm);
                    break;
            }
        }

        return pk;
    }

    UNPACKER_DBStruct::userID get_userID_data(const Packet::Tag::Ptr &user_pkt, const Packet::Key::Ptr &key) {
        Packet::Tag13::Ptr t13 = dynamic_pointer_cast<Packet::Tag13>(user_pkt);
        //boost::regex pattern("[\\w_.+-]+@[\\w.-]+\\.[\\w.-]+");
        //boost::smatch result;
        // get Email
        string user = t13->get_contents();
        string email = "";

        /*
        if (user.size() < 5000 && boost::regex_search(user, result, pattern)){
            email = result[0];
        }
        */
        /*
        std::regex mail_regex(
                "<(?:(?:[^<>()\\[\\].,;:\\s@\"]+(?:\\.[^<>()\\[\\].,;:\\s@\"]+)*)|\".+\")@(?:(?:[^<>()‌​\\[\\].,;:\\s@\"]+\\.)+[^<>()\\[\\].,;:\\s@\"]{2,})>");
        // get Email
        string user = t13->get_contents();
        string email = "";
        std::cmatch match;

        if (user.size() < 5000 && std::regex_search(user.c_str(), match, mail_regex)){
            email = string(match[0].first + 1, match[0].first + strlen(match[0].first) - 1);
		}
        */
        return UNPACKER_DBStruct::userID {
                .ownerkeyID = mpitodec(rawtompi(key->get_keyid())),
                .fingerprint = key->get_fingerprint(),
                .name = ascii2radix64(user),
                .email = ascii2radix64(email)
        };
    }


    void get_userAttributes_data(const Packet::Tag::Ptr &p, UNPACKER_DBStruct::userAtt &ua_struct) {
        Packet::Tag17::Ptr t17 = dynamic_pointer_cast<Packet::Tag17>(p);

        for (auto &a: t17->get_attributes()){
            switch (a->get_type()){
                case Subpacket::Tag17::IMAGE_ATTRIBUTE: {
                    Subpacket::Tag17::Sub1::Ptr s1t17 = static_pointer_cast<Subpacket::Tag17::Sub1>(a);
                    ua_struct.encoding = s1t17 -> get_encoding();
                    ua_struct.image = s1t17 -> get_image();
                    break;
                }
                default:
                    Subpacket::Tag17::SubWrong::Ptr swt17 = static_pointer_cast<Subpacket::Tag17::SubWrong>(a);
                    ua_struct.image = swt17 -> raw();
                    syslog(LOG_WARNING, "Not valid user attribute subpacket tag found: %d, saving anyway with encoding = 0", a->get_type());
                    break;
            }
        }
    }

    void get_tag2_subpackets_data(const std::vector<Subpacket::Tag2::Sub::Ptr> &subps, UNPACKER_DBStruct::signatures *ss) {
        for (auto &p : subps) {
            switch (p->get_type()) {
                case Subpacket::Tag2::SIGNATURE_CREATION_TIME:
                case Subpacket::Tag2::SIGNATURE_EXPIRATION_TIME:
                    break; //handled above
                case Subpacket::Tag2::EXPORTABLE_CERTIFICATION: {
                    Subpacket::Tag2::Sub4::Ptr s2 = dynamic_pointer_cast<Subpacket::Tag2::Sub4>(p);
                    ss->isExportable = s2->get_exportable();
                    break;
                }
                case Subpacket::Tag2::TRUST_SIGNATURE: {
                    Subpacket::Tag2::Sub5::Ptr s5 = dynamic_pointer_cast<Subpacket::Tag2::Sub5>(p);
                    ss->trustLevel = s5->get_level();
                    break;
                }
                case Subpacket::Tag2::REGULAR_EXPRESSION: {
                    Subpacket::Tag2::Sub6::Ptr s6 = dynamic_pointer_cast<Subpacket::Tag2::Sub6>(p);
                    ss->regex = ascii2radix64(s6->get_regex());
                    break;
                }
                case Subpacket::Tag2::REVOCABLE: {
                    Subpacket::Tag2::Sub7::Ptr s7 = dynamic_pointer_cast<Subpacket::Tag2::Sub7>(p);
                    ss->isRevocable = s7->get_revocable();
                    break;
                }
                case Subpacket::Tag2::KEY_EXPIRATION_TIME:
                    break; // Handled above
                case Subpacket::Tag2::PREFERRED_SYMMETRIC_ALGORITHMS: { // Preferred Symmetric Algorithms
                    Subpacket::Tag2::Sub11::Ptr s11 = dynamic_pointer_cast<Subpacket::Tag2::Sub11>(p);
                    ss->preferedSymmetric = s11->get_psa();
                    break;
                }
                case Subpacket::Tag2::REVOCATION_KEY: {
                    break; // Not in DB
                }
                case Subpacket::Tag2::ISSUER:
                    break; //Handled above
                case Subpacket::Tag2::NOTATION_DATA:
                    break; // Not in DB
                case Subpacket::Tag2::PREFERRED_HASH_ALGORITHMS: {
                    Subpacket::Tag2::Sub21::Ptr s21 = dynamic_pointer_cast<Subpacket::Tag2::Sub21>(p);
                    ss->preferedHash = s21->get_pha();
                    break;
                }
                case Subpacket::Tag2::PREFERRED_COMPRESSION_ALGORITHMS: {
                    Subpacket::Tag2::Sub22::Ptr s22 = dynamic_pointer_cast<Subpacket::Tag2::Sub22>(p);
                    ss->preferedCompression = s22->get_pca();
                    break;
                }
                case Subpacket::Tag2::KEY_SERVER_PREFERENCES:
                case Subpacket::Tag2::PREFERRED_KEY_SERVER:
                    break; // Not in DB
                case Subpacket::Tag2::PRIMARY_USER_ID: {
                    Subpacket::Tag2::Sub25::Ptr s25 = dynamic_pointer_cast<Subpacket::Tag2::Sub25>(p);
                    ss->isPrimaryUserId = s25->get_primary();
                    break;
                }
                case Subpacket::Tag2::POLICY_URI:
                    break; // Not in DB
                case Subpacket::Tag2::KEY_FLAGS: { // Key Flags
                    Subpacket::Tag2::Sub27::Ptr s27 = dynamic_pointer_cast<Subpacket::Tag2::Sub27>(p);
                    ss->flags = s27->get_flags();
                    break;
                }
                case Subpacket::Tag2::SIGNERS_USER_ID: {
                    Subpacket::Tag2::Sub28::Ptr s28 = dynamic_pointer_cast<Subpacket::Tag2::Sub28>(p);
                    ss->issuingUID = ascii2radix64(s28->get_signer());
                    break;
                }
                case Subpacket::Tag2::REASON_FOR_REVOCATION: {
                    Subpacket::Tag2::Sub29::Ptr s29 = dynamic_pointer_cast<Subpacket::Tag2::Sub29>(p);
                    ss->revocationCode = s29->get_code();
                    ss->revocationReason = ascii2radix64(s29->get_reason());
                    break;
                }
                case Subpacket::Tag2::FEATURES:
                    break; // Not in DB
                case Subpacket::Tag2::SIGNATURE_TARGET: {
                    Subpacket::Tag2::Sub31::Ptr s31 = dynamic_pointer_cast<Subpacket::Tag2::Sub31>(p);
                    ss->pubAlgorithm = s31->get_pka();
                    ss->signedHash = s31->get_hash();
                    ss->hashAlgorithm = s31->get_hash_alg();
                    break;
                }
                case Subpacket::Tag2::EMBEDDED_SIGNATURE:
                    break; // Not in DB
                #ifdef GPG_COMPATIBLE
                case Subpacket::Tag2::ISSUER_FINGERPRINT: {
                    Subpacket::Tag2::Sub33::Ptr s33 = dynamic_pointer_cast<Subpacket::Tag2::Sub33>(p);
                    ss->issuingFingerprint = s33->get_issuer_fingerprint();
                    break;
                }
                #endif
                default:
                    syslog(LOG_WARNING, "Not valid signature subpacket tag found: %d", p->get_type());
                    break;
            }
        }
    }
}
/*
bool operator==(const UNPACKER_DBStruct::signatures &s1, const UNPACKER_DBStruct::signatures &s2){
    return s1.s == s2.s && s1.r == s2.r;
}
 */
