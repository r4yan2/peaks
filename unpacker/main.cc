#include <iostream>
#include <thread>
#include <cstring>
#include <random>
#include <climits>
#include "DBManager.h"
#include "Thread_Pool.h"
#include "unpacker.h"
#include <functional>
#include <Misc/radix64.h>
#include <Key.h>
#include <syslog.h>
#include <future>

using namespace std;
using namespace OpenPGP;

void printHelp();

int main(int argc, char* argv[]) {

    cout << Utils::getCurrentTime() << "Starting unpacker" << endl;

    openlog("pgp_analyzer", LOG_PID, LOG_USER);
    setlogmask (LOG_UPTO (LOG_NOTICE));
    syslog(LOG_NOTICE, "Unpacker daemon is starting up!");
    unsigned int nThreads = thread::hardware_concurrency() / 2;
    unsigned long limit = Utils::MAX_LIMIT;
    unsigned int key_per_thread = Utils::KEY_PER_THREAD_DEFAULT;
    const char *MINUS_T = "-t";
    const char *MINUS_L = "-l";
    const char *MINUS_H = "-h";
    const char *MINUS_K = "-k";

    for (int i = 1; i < argc; i++){
        if(!strcmp(argv[i], MINUS_H)){
            printHelp();
            exit(0);
        }
        else if(!strcmp(argv[i], MINUS_T)){
            try{
                nThreads = static_cast<unsigned int>(stoul(argv[++i]));
            }catch (...){
                nThreads = thread::hardware_concurrency() / 2;
            }
        }
        else if(!strcmp(argv[i], MINUS_L)){
            try{
                limit = stoul(argv[++i]);
            }catch (...){
                limit = Utils::MAX_LIMIT;
            }
        }
        else if(!strcmp(argv[i], MINUS_K)){
            try{
                key_per_thread = static_cast<unsigned int>(stoul(argv[++i]));
            }catch (...){
                key_per_thread = Utils::KEY_PER_THREAD_DEFAULT;
            }
        }
        else{
            cout << "Option not recognized: " << argv[i] << endl;
            exit(0);
        }
    }

    if(Utils::create_folders() == -1){
        cerr << "Unable to create temp folder" << endl;
        exit(-1);
    }

    cout << "Threads: " << nThreads << endl;
    cout << "Limit: " << limit << endl;
    cout << "Key per Thread: " << key_per_thread << endl;

    shared_ptr<DBManager> dbm = make_shared<DBManager>();

    vector<DBStruct::gpg_keyserver_data> gpg_data = dbm->get_certificates(limit);

    shared_ptr<Thread_Pool> pool = make_shared<Thread_Pool>();
    vector<thread> pool_vect(nThreads);

    for (unsigned int i = 0; i < nThreads; i++){
        pool_vect[i] = thread([=] { pool->Infinite_loop_function(); });
    }

    for (unsigned int i = 0; i < gpg_data.size();){
        vector<PublicKey::Ptr> pks;
        for (unsigned int j = 0; i < gpg_data.size() && j < key_per_thread; j++, i++){
            try{
                std::stringstream s(gpg_data[i].certificate);
                PGP::Ptr pkt(new PGP(s, true));
                pkt -> set_type(PGP::PUBLIC_KEY_BLOCK);
                pks.push_back(make_shared<PublicKey>(PublicKey(*pkt)));
            }catch (exception &e){
                dbm->set_as_not_analyzable(gpg_data[i].version, gpg_data[i].fingerprint, "Error during creation of the object PGP::Key");
                syslog(LOG_CRIT, "Error during creation of the object PGP::Key - %s", e.what());
                continue;
            }catch (error_code &e){
                dbm->set_as_not_analyzable(gpg_data[i].version, gpg_data[i].fingerprint, "Error during creation of the object PGP::Key");
                syslog(LOG_CRIT, "Error during creation of the object PGP::Key - %s", e.message().c_str());
                continue;
            }
        }
        pool->Add_Job([=] { return Unpacker::unpack_key_th(pks); });
    }

    pool->Stop_Filling_UP();

    for (auto &th: pool_vect){
        while (!th.joinable()){}
        th.join();
    }

    cout << Utils::getCurrentTime() << "Writing in DB" << endl;

    dbm->insertCSV(Utils::get_files(Utils::PUBKEY), Utils::PUBKEY);
    dbm->insertCSV(Utils::get_files(Utils::USER_ATTRIBUTES), Utils::USER_ATTRIBUTES);
    dbm->insertCSV(Utils::get_files(Utils::SIGNATURE), Utils::SIGNATURE);
    dbm->insertCSV(Utils::get_files(Utils::SELF_SIGNATURE), Utils::SELF_SIGNATURE);
    dbm->insertCSV(Utils::get_files(Utils::UNPACKED), Utils::UNPACKED);
    dbm->insertCSV(Utils::get_files(Utils::UNPACKER_ERRORS), Utils::UNPACKER_ERRORS);

    cout << Utils::getCurrentTime() << "Start filling empty issuing fingerprints" << endl;
    dbm->UpdateSignatureIssuingFingerprint(limit);

    cout << Utils::getCurrentTime() << "Updating issuing username in Signatures" << endl;
    dbm->UpdateSignatureIssuingUsername();

    cout << Utils::getCurrentTime() << "Setting expired flag" << endl;
    dbm->UpdateIsExpired();

    cout << Utils::getCurrentTime() << "Setting revoked flag" << endl;
    dbm->UpdateIsRevoked();

    cout << Utils::getCurrentTime() << "Setting valid flag" << endl;
    dbm->UpdateIsValid();

    syslog(LOG_NOTICE, "Unpacker daemon is stopping!");

    cout << Utils::getCurrentTime() << "Unpacking terminated" << endl;

    return 0;
}

void printHelp() {
    cout << "Parameters:" << endl;
    cout << "-t: set number of threads" << endl;
    cout << "-l: set how many keys to analyze" << endl;
    cout << "The default value for this computer are:" << endl;
    cout << "t = " << thread::hardware_concurrency() / 2 << endl;
    cout << "l = " << Utils::MAX_LIMIT << endl;
}