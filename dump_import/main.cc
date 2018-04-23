#include <iostream>
#include <syslog.h>
#include <thread>
#include <cstring>
#include "DBManager.h"
#include "Thread_Pool.h"
#include "utils.h"
#include "unpacker.h"

using namespace Utils;
using namespace std;
using namespace std::chrono_literals;

void printHelp();

int main(int argc, char* argv[]) {

    cout << Utils::getCurrentTime() << "Starting unpacker" << endl;

    openlog("pgp_dump_import", LOG_PID, LOG_USER);
    setlogmask (LOG_UPTO (LOG_NOTICE));
    syslog(LOG_NOTICE, "Dump_import is starting up!");
    unsigned int nThreads = thread::hardware_concurrency() / 2;
    unsigned int key_per_thread = KEY_PER_THREAD_DEFAULT;
    boost::filesystem::path path = DEFAULT_DUMP_PATH;
    const char *MINUS_T = "-t";
    const char *MINUS_P = "-p";
    const char *MINUS_H = "-h";
    const char *MINUS_K = "-k";

    for (int i = 1; i < argc; i++){
        if(!strcmp(argv[i], MINUS_H)){
            printHelp();
            exit(0);
        }
        else if(!strcmp(argv[i], MINUS_P)){
            try{
                path = argv[++i];
            }catch (...){
                path = DEFAULT_DUMP_PATH;
            }
        }
        else if(!strcmp(argv[i], MINUS_T)){
            try{
                nThreads = static_cast<unsigned int>(stoul(argv[++i]));
            }catch (...){
                nThreads = thread::hardware_concurrency() / 2;
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
    cout << "Key per Thread: " << key_per_thread << endl;

    shared_ptr<DBManager> dbm = make_shared<DBManager>();

    cout << Utils::getCurrentTime() << "Starting dump read" << endl;

    vector<string> files;
    try {
        files = Utils::get_dump_files(path);
    }catch (exception &e){
        cerr << "Unable to read dump folder/files" << endl;
        exit(-1);
    }

    shared_ptr<Thread_Pool> pool = make_shared<Thread_Pool>();
    vector<thread> pool_vect(nThreads);

    for (unsigned int i = 0; i < nThreads; i++){
        pool_vect[i] = thread([=] { pool->Infinite_loop_function(); });
    }

    for (unsigned int i = 0; i < files.size();){
        vector<string> dump_file_tmp;
        for (unsigned int j = 0; i < files.size() && j < key_per_thread; j++, i++){
            dump_file_tmp.push_back(files[i]);
        }
        pool->Add_Job([=] { return Unpacker::unpack_dump_th(dump_file_tmp); });
    }

    pool->Stop_Filling_UP();

    for (auto &th: pool_vect){
        while (!th.joinable()){}
        th.join();
    }

    cout << Utils::getCurrentTime() << "Writing dumped packet in DB:" << endl;

    dbm->lockTables();
    cout << Utils::getCurrentTime() << "\tInserting Certificates" << endl;
    dbm->insertCSV(Utils::get_files(Utils::CERTIFICATE), Utils::CERTIFICATE);
    cout << Utils::getCurrentTime() << "\tInserting Pubkeys" << endl;
    dbm->insertCSV(Utils::get_files(Utils::PUBKEY), Utils::PUBKEY);
    cout << Utils::getCurrentTime() << "\tInserting UserID" << endl;
    dbm->insertCSV(Utils::get_files(Utils::USERID), Utils::USERID);
    cout << Utils::getCurrentTime() << "\tInserting User Attributes" << endl;
    dbm->insertCSV(Utils::get_files(Utils::USER_ATTRIBUTES), Utils::USER_ATTRIBUTES);
    cout << Utils::getCurrentTime() << "\tInserting Signatures" << endl;
    dbm->insertCSV(Utils::get_files(Utils::SIGNATURE), Utils::SIGNATURE);
    cout << Utils::getCurrentTime() << "\tInserting SelfSignatures" << endl;
    dbm->insertCSV(Utils::get_files(Utils::SELF_SIGNATURE), Utils::SELF_SIGNATURE);
    cout << Utils::getCurrentTime() << "\tInserting Unpacker Errors" << endl;
    dbm->insertCSV(Utils::get_files(Utils::UNPACKER_ERRORS), Utils::UNPACKER_ERRORS);
    cout << Utils::getCurrentTime() << "\tInserting Broken Keys" << endl;
    dbm->insertCSV(Utils::get_files(Utils::BROKEN_KEY), Utils::BROKEN_KEY);

    cout << Utils::getCurrentTime() << "Updating DB fields:" << endl;

    cout << Utils::getCurrentTime() << "\tUpdating issuing fingerprint in Signatures" << endl;
    dbm->UpdateSignatureIssuingFingerprint();

    cout << Utils::getCurrentTime() << "\tUpdating issuing username in Signatures" << endl;
    dbm->UpdateSignatureIssuingUsername();

    cout << Utils::getCurrentTime() << "\tSetting expired flag" << endl;
    dbm->UpdateIsExpired();

    cout << Utils::getCurrentTime() << "\tSetting valid flag" << endl;
    dbm->UpdateIsValid();

    dbm->unlockTables();

    syslog(LOG_NOTICE, "Dump_import is stopping!");

    cout << Utils::getCurrentTime() << "Dump_import terminated. Remember to create the ptree with the SKS executable "
            "before starting the recon." << endl;



    return 0;
}

void printHelp() {
    cout << "Parameters:" << endl;
    cout << "-t: set number of threads" << endl;
    cout << "-k: set how many keys a thread has to analyze" << endl;
    cout << "-p: set the path of the dump" << endl;
    cout << "The default value for this computer are:" << endl;
    cout << "t = " << thread::hardware_concurrency() / 2 << endl;
    cout << "k = " << KEY_PER_THREAD_DEFAULT << endl;
    cout << "p = " << DEFAULT_DUMP_PATH << endl;
}