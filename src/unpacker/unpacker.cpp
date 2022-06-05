#include <ctime>
#include <Packets/Packets.h>
#include <Misc/mpi.h>
#include <Misc/sigcalc.h>
#include <common/errors.h>
#include <cmath>
#include <Misc/PKCS1.h>
#include "DBStruct.h"
#include "PKA/PKAs.h"
#include "Packets/Tag2/Subpacket.h"
#include "unpacker.h"
#include "Key_Tools.h"
#include "utils.h"
#include <common/config.h>

namespace peaks{
namespace unpacker{

void blocklist(){
    std::shared_ptr<UNPACKER_DBManager> dbm = std::make_shared<UNPACKER_DBManager>();
    auto blocklist = CONTEXT.get<std::vector<std::string>>("ID");
    for (auto & ID: blocklist){
        auto kid = Utils::hexToUll(ID);
        dbm->insert_into_blocklist(kid);
        dbm->remove_key_from_db(kid);
    }
}

void unpack(){
    Unpacker u;
    int iterations = CONTEXT.get<int>("only");
    while(true) {
    	u.run();
        if (iterations > 0)
            iterations--;
        if (iterations == 0){
            syslog(LOG_INFO, "Done %d iterations!", CONTEXT.get<int>("only"));
            break;
        }
    	std::this_thread::sleep_for(std::chrono::seconds{CONTEXT.get<int>("unpacker_interval")});
    }
}

using namespace std;
using namespace OpenPGP;

Unpacker::Unpacker(){
    syslog(LOG_NOTICE, "Unpacker daemon is starting up!");

    nThreads = CONTEXT.get<int>("threads", CONTEXT.get<int>("unpacker_threads"));
    syslog(LOG_NOTICE, "Using %d Threads", nThreads);

    limit = CONTEXT.get<int>("limit", CONTEXT.get<int>("unpacker_limit"));
    syslog(LOG_INFO, "limiting analysis at %d keys", limit);

    if(Utils::create_folders(CONTEXT.get<std::string>("tmp_folder")) == -1){
        syslog(LOG_WARNING,  "Unable to create temp folder");
        exit(-1);
    }

    if (Utils::create_folders(CONTEXT.get<std::string>("error_folder")) == -1){
        syslog(LOG_WARNING,  "Unable to create error folder");
        exit(-1);
    }
    
    std::shared_ptr<UNPACKER_DBManager> dbm = std::make_shared<UNPACKER_DBManager>();
    if (CONTEXT.get<bool>("reset")){
        //reset unpacking status
        dbm->begin_transaction();
        dbm->execute_query("truncate Pubkey");
        dbm->execute_query("truncate Signatures");
        dbm->execute_query("truncate selfSignaturesMetadata");
        dbm->execute_query("truncate UserID");
        dbm->execute_query("truncate UserAttribute");
        dbm->execute_query("truncate Unpacker_errors");
        dbm->execute_query("UPDATE gpg_keyserver SET is_unpacked = 0");
        dbm->end_transaction();
        std::cout << "Unpacker status reset completed!" << std::endl;
        exit(0);
    }

    std::vector<std::string> error_files = Utils::dirlisting(CONTEXT.get<std::string>("error_folder"));
    if (error_files.size() > 0){
        std::cout << "Found files in unpacker error folder, proceding to error recovery" << std::endl;
        std::cout << "List of files to recover:" << std::endl;
        for (auto &f: error_files)
        {
            std::cout << "\t" << f << std::endl;
            std::vector<std::string> fullpath, filename;
            boost::split(fullpath, f, boost::is_any_of("/"));
            for (auto const &x: Utils::FILENAME){
                if (Utils::hasEnding(fullpath.back(), x.second)){
                    dbm->insertCSV(f, x.first);
                }
            }
        }
    }
    
    key_per_thread = 1 + ((limit - 1)/nThreads);
}

void Unpacker::run(){

    std::shared_ptr<UNPACKER_DBManager> dbm = std::make_shared<UNPACKER_DBManager>();
    // resume session if any
    std::string res = "";
    dbm->get_from_cache("unpacker", res);
    if (res != "")
        store_keymaterial(dbm);
    
    if (CONTEXT.get<bool>("recover")){
        std::cout << "Finished recovery, exiting" << std::endl;
        exit(0);
    }

    std::shared_ptr<DBResult> results = dbm->get_certificates_iterator(limit);

    if (!results->size()){
        std::cout << "No data to process, going to sleep" << std::endl;
        return;
    }
    
    std::shared_ptr<Thread_Pool> pool = std::make_shared<Thread_Pool>(nThreads);

    dbm->openCSVFiles();

    for (size_t i = 0; i < results->size(); i+=key_per_thread){
        pool->Add_Job(std::make_shared<Job>([=, &dbm, &results] {unpack_key_th(dbm, results, i, key_per_thread); }));
    }
    pool->terminate();

    dbm->flushCSVFiles();
    dbm->closeCSVFiles();
    store_keymaterial(dbm);

    syslog(LOG_NOTICE, "Unpacker daemon is stopping!");
}

void unpack_key_th(const std::shared_ptr<UNPACKER_DBManager> &dbm_, const std::shared_ptr<DBResult> & results, size_t start, size_t size) {
    std::shared_ptr<UNPACKER_DBManager> dbm = make_shared<UNPACKER_DBManager>();
    dbm->openCSVFiles(); // just recover handlers
    int max_bin_size = CONTEXT.get<int>("max_unpacker_keysize");
    size_t end = start + size;
    for (size_t i = start; i < results->size() && i < end; i++){
        DBStruct::gpg_keyserver_data gpg_data = dbm_->get_certificate_from_results(results);
        Key::Ptr key;
        bool analyzable = true;
        try{
            key = std::make_shared<Key>();
            key->read_raw(gpg_data.certificate);
            key->set_type(PGP::PUBLIC_KEY_BLOCK);
        }catch (std::error_code &ec){
            switch (ec.value()) {
                case static_cast<int>(KeyErrc::NotExistingVersion):
                case static_cast<int>(KeyErrc::BadKey):
                case static_cast<int>(KeyErrc::NotAPublicKey):
                case static_cast<int>(KeyErrc::NotASecretKey):
                    analyzable = false;
                    break;
                case static_cast<int>(KeyErrc::NotEnoughPackets): {
                    if (key->get_packets().empty()) {
                        analyzable = false;
                        break;
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
                    break;
                default:
                    analyzable = false;
                    break;
            }
            
            if (!analyzable){
                syslog(LOG_WARNING, "Error during creation of the object PGP::Key - %s at index %lu", ec.message().c_str(), i);
                dbm->set_as_not_analyzable(gpg_data.version, gpg_data.fingerprint, "Error during creation of the object PGP::Key");
                continue;
            }
        }catch (std::exception &e){
            syslog(LOG_WARNING, "Error during creation of the object PGP::Key - %s at index %lu", e.what(), i);
            dbm->set_as_not_analyzable(gpg_data.version, gpg_data.fingerprint, "Error during creation of the object PGP::Key");
            continue;
        }catch (...){
            syslog(LOG_WARNING, "Error during creation of the object PGP::Key at index %lu", i);
            continue;
        }

        if (max_bin_size > 0 && max_bin_size < gpg_data.certificate.size()){
            dbm->set_as_not_analyzable(gpg_data.version, gpg_data.fingerprint, "Key skipped: too large");
            continue;
        }

        // only unpackable key after this point
        assert(analyzable);

        // actual unpack
        try{
            unpack_key(key, dbm);
        }catch(exception &e) {
            syslog(LOG_WARNING, "Key not analyzed due to not meaningfulness (%s). is_analyzed will be set equals to -1", e.what());
            cout << "Key not analyzed due to not meaningfulness (" << e.what() << "). is_analyzed will be set equals to -1" << endl;
            dbm->set_as_not_analyzable(key->version(), key->fingerprint(), e.what());
            continue;
        }catch (error_code &ec){
            syslog(LOG_WARNING, "Key not unpacked due to not meaningfulness (%s).", ec.message().c_str());
            cerr << "Key not unpacked due to not meaningfulness (" << ec.message() << ")." << endl;
            dbm->set_as_not_analyzable(key->version(), key->fingerprint(), ec.message());
            continue;
        }catch (...){
            syslog(LOG_CRIT, "Error during creation of the object PGP::Key");
            continue;
        }
    } //end for
    dbm->flushCSVFiles();
}

void Unpacker::store_keymaterial(const std::shared_ptr<UNPACKER_DBManager> &dbm){
    if (CONTEXT.get<bool>("csv-only", false))
        return; //nothing to do
    dbm->store_in_cache("unpacker", "saving");
    dbm->insertCSV();
    dbm->store_in_cache("unpacker", "");
    //dbm->UpdateSignatureIssuingFingerprint();
    //dbm->UpdateSignatureIssuingUsername();
    //dbm->UpdateIsExpired();
    //dbm->UpdateIsRevoked();
    //dbm->UpdateIsValid();
}

void unpack_key( const Key::Ptr &key, shared_ptr<UNPACKER_DBManager> &dbm){

    Key::pkey pk;
    DBStruct::Unpacker_errors modified;

    try{
        modified.version = key->version();
        modified.fingerprint = key->fingerprint();
        std::shared_ptr<std::map<int, std::string>> errors = make_shared<std::map<int, std::string>>();
        OpenPGP::Key::meaningful(*key, errors);
        pk = key->get_pkey();
        Key_Tools::makePKMeaningful(pk, modified);
    }catch (error_code &ec){
        switch (ec.value()) {
            case static_cast<int>(KeyErrc::NotExistingVersion):
                syslog(LOG_WARNING, "Error: PGP Packet doesn't have a valid version number");
                throw ec;
            case static_cast<int>(KeyErrc::BadKey):
                syslog(LOG_WARNING, "Submitted a PGP packet of type: %d", key->get_type());
                throw ec;
            case static_cast<int>(KeyErrc::NotAPublicKey):
                syslog(LOG_WARNING, "Submitted a private key!");
                throw ec;
            case static_cast<int>(KeyErrc::NotASecretKey):
                throw runtime_error("Not unpackable key: " + ec.message());
            case static_cast<int>(KeyErrc::NotEnoughPackets): {
                    PGP::Packets ps = key->get_packets();
                    if (ps.empty()) {
                        throw std::runtime_error("No packets found inside the key");
                    } else if (ps[0]->get_tag() != Packet::PUBLIC_KEY) {
                        throw std::runtime_error("No primary key packet found");
                    } else {
                        // TODO add error to the errors map
                        pk = Key_Tools::readPkey(key, modified);
                    }
                    break;
                }
            case static_cast<int>(KeyErrc::FirstPacketWrong): {
                    bool found = false;
                    Key::Packets p_list = key->get_packets();
                    for (auto packet = p_list.begin(); packet != p_list.end(); packet++){
                        if ((*packet)->get_tag() == Packet::PUBLIC_KEY){
                            Packet::Tag::Ptr tempPacket = *packet;
                            p_list.erase(packet);
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
            case static_cast<int>(KeyErrc::NotAllPacketsAnalyzed):
                pk = Key_Tools::readPkey(key, modified);
                Key_Tools::makePKMeaningful(pk, modified);
                break;
            case static_cast<int>(ParsingErrc::LengthLEQZero):
            case static_cast<int>(ParsingErrc::PubkeyAlgorithmNotFound):
            case static_cast<int>(ParsingErrc::PubkeyVersionNotFound):
            case static_cast<int>(ParsingErrc::ParsingError):
            case static_cast<int>(ParsingErrc::SignaturePKANotFound):
            case static_cast<int>(ParsingErrc::SignatureHashNotFound):
            case static_cast<int>(ParsingErrc::SignatureVersionNotFound):
            case static_cast<int>(ParsingErrc::SignatureLengthWrong):
                throw std::runtime_error("Cannot parse: " + ec.message());

            default:
                throw runtime_error("Not unpackable key: " + ec.message());
        }

    }

    Packet::Key::Ptr primaryKey = static_pointer_cast<Packet::Key>(pk.key);
    deque<DBStruct::pubkey> unpackedPubkeys;
    deque<DBStruct::userID> unpackedUserID;
    deque<DBStruct::userAtt> unpackedUserAttributes;
    deque<DBStruct::signatures> unpackedSignatures; // contains also self-signatures

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
            unpackedSignatures.push_back(get_signature_data(i, primaryKey, uatt_id));
        }catch (exception &e){
            modified.modified = true;
            modified.comments.push_back("Unpacking jumped due to: " + string(e.what()));
        }
    }

    for (auto it = pk.uid_userAtt.begin(); it != pk.uid_userAtt.end(); it++) {
        try {
            DBStruct::userAtt ua_struct{
                    .id = std::distance(pk.uid_userAtt.begin(), it) + 1,
                    .fingerprint = primaryKey->get_fingerprint(),
                    .name = dynamic_pointer_cast<Packet::Tag13>(it->first)->get_contents()
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
    while(!unpackedUserID.empty()){
        auto u = unpackedUserID.front();
        dbm->write_userID_csv(u);
        unpackedUserID.pop_front();
    }
    while(!unpackedUserAttributes.empty()){
        auto u = unpackedUserAttributes.front();
        dbm->write_userAttributes_csv(u);
        unpackedUserAttributes.pop_front();
    }
    while(!unpackedSignatures.empty()){
        auto it = unpackedSignatures.front();
        dbm->write_signature_csv(it);
        if (it.issuingKeyId == it.signedKeyId && !it.signedUsername.empty()){
            dbm->write_self_signature_csv(it);
        }
        unpackedSignatures.pop_front(); //release memory
    }

    dbm->write_unpackerErrors_csv(modified);
    dbm->write_unpacked_csv(key, modified);
}

DBStruct::signatures get_signature_data(const Key::SigPairs::iterator &sp, const Packet::Key::Ptr &priKey, const string &uatt_id) {
    DBStruct::signatures ss;
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
            ss.signedUsername.set_f([=]{return ascii2radix64(u -> get_contents());});
            ss.signedUsername.set_empty(u -> get_contents().empty());
        }else{
            if (uatt_id != "")
                ss.uatt_id = uatt_id;
        }

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
                ss.sString = mpitoraw(algValues[0]);
            break;
        case PKA::ID::DSA:
        case PKA::ID::ECDSA:
        case PKA::ID::EdDSA:
            if (algValues.size() > 1){
                ss.rString = mpitoraw(algValues[0]);
                ss.sString = mpitoraw(algValues[1]);
            }
            break;
        case PKA::ID::RESERVED_ELGAMAL:
            //TODO obsolete
            if (algValues.size() > 0) 
                ss.sString = mpitoraw(algValues[0]);
            break; 
        default:
            syslog(LOG_ERR, "Not valid/implemented algorithm found: %i", ss.pubAlgorithm);
            break;
    }

    return ss;
}

void handle_wrong_sig(DBStruct::signatures &ss, const Packet::Key::Ptr &key, const Packet::Key::Ptr &subkey,
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

void handle_wrong_sig(DBStruct::signatures &ss, const Packet::Key::Ptr &key, const Packet::User::Ptr &user,
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

DBStruct::pubkey get_publicKey_data(const Packet::Tag::Ptr &p, const Packet::Key::Ptr &priKey) {
    Packet::Key::Ptr k = dynamic_pointer_cast<Packet::Key>(p);
    DBStruct::pubkey pk;

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
            unsigned long t = k->get_expire();
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
            case PKA::ID::RESERVED_ELGAMAL:
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

DBStruct::userID get_userID_data(const Packet::Tag::Ptr &user_pkt, const Packet::Key::Ptr &key) {
    Packet::Tag13::Ptr t13 = dynamic_pointer_cast<Packet::Tag13>(user_pkt);
    return DBStruct::userID {
            .ownerkeyID = mpitodec(rawtompi(key->get_keyid())),
            .fingerprint = key->get_fingerprint(),
            .name = t13->get_contents()
    };
}


void get_userAttributes_data(const Packet::Tag::Ptr &p, DBStruct::userAtt &ua_struct) {
    Packet::Tag17::Ptr t17 = dynamic_pointer_cast<Packet::Tag17>(p);

    for (auto &a: t17->get_attributes()){
        switch (a->get_type()){
            case Subpacket::Tag17::IMAGE_ATTRIBUTE: {
                Subpacket::Tag17::Sub1::Ptr s1t17 = static_pointer_cast<Subpacket::Tag17::Sub1>(a);
                ua_struct.encoding = s1t17 -> get_encoding();
                ua_struct.image = Utils::Lazystring([=]{return hexlify(s1t17 -> get_image());}, s1t17->raw().empty());
                break;
            }
            default:
                Subpacket::Tag17::SubWrong::Ptr swt17 = static_pointer_cast<Subpacket::Tag17::SubWrong>(a);
                ua_struct.image = Utils::Lazystring([=]{return hexlify(swt17 -> raw());}, swt17->raw().empty());
                syslog(LOG_WARNING, "Not valid user attribute subpacket tag found: %d, saving anyway with encoding = 0", a->get_type());
                break;
        }
    }
}

void get_tag2_subpackets_data(const std::vector<Subpacket::Tag2::Sub::Ptr> &subps, DBStruct::signatures *ss) {
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
                ss->regex = s6->get_regex();
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
                ss->issuingUsername = Utils::Lazystring([=]{return ascii2radix64(s28->get_signer());}, s28->get_signer().empty());
                break;
            }
            case Subpacket::Tag2::REASON_FOR_REVOCATION: {
                Subpacket::Tag2::Sub29::Ptr s29 = dynamic_pointer_cast<Subpacket::Tag2::Sub29>(p);
                ss->revocationCode = s29->get_code();
                ss->revocationReason = s29->get_reason();
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
            case Subpacket::Tag2::ISSUER_FINGERPRINT: {
                Subpacket::Tag2::Sub33::Ptr s33 = dynamic_pointer_cast<Subpacket::Tag2::Sub33>(p);
                ss->issuingFingerprint = s33->get_issuer_fingerprint();
                break;
            }
            default:
                auto type = p->get_type();
                if (Subpacket::Tag2::NAME.count(type) == 0)
                    syslog(LOG_WARNING, "Not valid signature subpacket tag found: %d", p->get_type());
                break;
        }
    }
}

}
}
