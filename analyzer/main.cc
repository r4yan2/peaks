#include <iostream>
#include <syslog.h>
#include <thread>
#include <cstring>
#include "DBManager.h"
#include "Thread_Pool.h"
#include "analyzer.h"
#include "utils.h"

using namespace Utils;
using namespace std;

void printHelp();

int main(int argc, char* argv[]) {

    cout << Utils::getCurrentTime() << "Starting unpacker" << endl;

    openlog("pgp_analyzer", LOG_PID, LOG_USER);
    setlogmask (LOG_UPTO (LOG_NOTICE));
    syslog(LOG_NOTICE, "Analyzer daemon is starting up!");
    unsigned int nThreads = thread::hardware_concurrency() / 2;
    unsigned long limit = MAX_LIMIT;
    unsigned int key_per_thread = KEY_PER_THREAD_DEFAULT;
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
                limit = MAX_LIMIT;
            }
        }
        else if(!strcmp(argv[i], MINUS_K)){
            try{
                key_per_thread = static_cast<unsigned int>(stoul(argv[++i]));
            }catch (...){
                key_per_thread = KEY_PER_THREAD_DEFAULT;
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

    Analyzer a = Analyzer();

    cout << Utils::getCurrentTime() << "Starting pubkey analysis" << endl;

    vector<DBStruct::pubkey> pk = dbm->get_pubkey(limit);
    bool exist_rsa = false;

    shared_ptr<Thread_Pool> pool = make_shared<Thread_Pool>();
    vector<thread> pool_vect(nThreads);

    for (unsigned int i = 0; i < nThreads; i++){
        pool_vect[i] = thread([=] { pool->Infinite_loop_function(); });
    }

    for (unsigned int i = 0; i < pk.size();){
        vector<DBStruct::pubkey> pks;
        exist_rsa = PKA::is_RSA(pk[i].pubAlgorithm);
        for (unsigned int j = 0; i < pk.size() && j < key_per_thread; j++, i++){
            pks.push_back(pk[i]);
        }
        pool->Add_Job([=] { return a.analyze_pubkeys(pks); });
    }

    pool->Stop_Filling_UP();

    for (auto &th: pool_vect){
        while (!th.joinable()){}
        th.join();
    }


    cout << Utils::getCurrentTime() << "Writing analyzed pubkeys in DB" << endl;

    dbm->insertCSV(Utils::get_files(Utils::BROKEN_PUBKEY), Utils::BROKEN_PUBKEY);
    dbm->insertCSV(Utils::get_files(Utils::ANALYZED_PUBKEY), Utils::ANALYZED_PUBKEY);

    cout << Utils::getCurrentTime() << "Starting RSA modulus analysis" << endl;

    if (!pk.empty() && exist_rsa){
        a.analyze_RSA_modulus_common_factor(dbm, nThreads);
    }

    cout << Utils::getCurrentTime() << "Writing analyzed pubkeys in DB" << endl;

    dbm->insertCSV(Utils::get_files(Utils::BROKEN_MODULUS), Utils::BROKEN_MODULUS);

    cout << Utils::getCurrentTime() << "Starting signature analysis" << endl;

    vector<DBStruct::signatures> ss = dbm->get_signatures(limit);

    pool->Start_Filling_UP();

    for (unsigned int i = 0; i < nThreads; i++){
        pool_vect[i] = thread([=] { pool->Infinite_loop_function(); });
    }

    for (unsigned int i = 0; i < ss.size();){
        vector<DBStruct::signatures> sss;
        for (unsigned int j = 0; i < ss.size() && j < key_per_thread; i++, j++){
            sss.push_back(ss[i]);
        }
        pool->Add_Job([=] { return a.analyze_signatures(sss); });
    }

    pool->Add_Job([=] { return dbm->write_repeated_r_csv(); });

    pool->Stop_Filling_UP();

    for (auto &th: pool_vect){
        while (!th.joinable()){}
        th.join();
    }

    cout << Utils::getCurrentTime() << "Writing analyzed signatures in DB" << endl;

    dbm->insertCSV(Utils::get_files(Utils::BROKEN_SIGNATURE), Utils::BROKEN_SIGNATURE);
    dbm->insertCSV(Utils::get_files(Utils::REPEATED_R), Utils::REPEATED_R);
    dbm->insertCSV(Utils::get_files(Utils::ANALYZED_SIGNATURE), Utils::ANALYZED_SIGNATURE);

    syslog(LOG_NOTICE, "Analyzer daemon is stopping!");

    cout << Utils::getCurrentTime() << "Analyzing terminated" << endl;


    return 0;
}

void printHelp() {
    cout << "Parameters:" << endl;
    cout << "-t: set number of threads" << endl;
    cout << "-l: set how many keys to analyze" << endl;
    cout << "-k: set how many keys a thread should analyze at a time" << endl;
    cout << "The default value for this computer are:" << endl;
    cout << "t = " << thread::hardware_concurrency() / 2 << endl;
    cout << "l = " << MAX_LIMIT << endl;
    cout << "k = " << KEY_PER_THREAD_DEFAULT << endl;
}