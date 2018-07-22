#include "dump_import.h"

using namespace Utils;
using namespace std;
using namespace std::chrono_literals;

vector<string> get_hashes(const vector<string> &files){
    vector<string> hashes;
    for (const auto &file: files){
        string line;
        string hash;
        ifstream read(file);
        while (getline(read, line))
        {
            istringstream iss(line);
            for (int i=0; i<4; i++)
                getline(iss, hash, ',');
            getline(iss, hash, ',');
            hash = hash.substr(1, hash.size()-2);
            hashes.push_back(hash);
        }
    }
    return hashes;
}

vector<string> dump_import(vector<string> keys){

    openlog("pgp_dump_import", LOG_PID, LOG_USER);
    setlogmask (LOG_UPTO (LOG_NOTICE));
    syslog(LOG_NOTICE, "Dump_import is starting up!");
    unsigned int nThreads = thread::hardware_concurrency() / 2;
    unsigned int key_per_thread = KEY_PER_THREAD_DEFAULT;
    boost::filesystem::path path = DEFAULT_DUMP_PATH;
    path = DEFAULT_DUMP_PATH;
    nThreads = thread::hardware_concurrency() / 2;
    key_per_thread = KEY_PER_THREAD_DEFAULT;

    if(Utils::create_folders() == -1){
        exit(-1);
    }

    shared_ptr<DBManager> dbm = make_shared<DBManager>();

    shared_ptr<Thread_Pool> pool = make_shared<Thread_Pool>();
    vector<thread> pool_vect(nThreads);

    for (unsigned int i = 0; i < nThreads; i++){
        pool_vect[i] = thread([=] { pool->Infinite_loop_function(); });
    }

    for (unsigned int i = 0; i < keys.size();){
        vector<string> dump_file_tmp;
        for (unsigned int j = 0; i < keys.size() && j < key_per_thread; j++, i++){
            dump_file_tmp.push_back(keys[i]);
        }
        pool->Add_Job([=] { return Unpacker::unpack_dump_th(dump_file_tmp); });
    }

    pool->Stop_Filling_UP();

    for (auto &th: pool_vect){
        while (!th.joinable()){}
        th.join();
    }


    dbm->lockTables();
    vector<string> hashes = get_hashes(Utils::get_files(Utils::CERTIFICATE));
    dbm->insertCSV(Utils::get_files(Utils::CERTIFICATE), Utils::CERTIFICATE);
    dbm->insertCSV(Utils::get_files(Utils::PUBKEY), Utils::PUBKEY);
    dbm->insertCSV(Utils::get_files(Utils::USERID), Utils::USERID);
    dbm->insertCSV(Utils::get_files(Utils::USER_ATTRIBUTES), Utils::USER_ATTRIBUTES);
    dbm->insertCSV(Utils::get_files(Utils::SIGNATURE), Utils::SIGNATURE);
    dbm->insertCSV(Utils::get_files(Utils::SELF_SIGNATURE), Utils::SELF_SIGNATURE);
    dbm->insertCSV(Utils::get_files(Utils::UNPACKER_ERRORS), Utils::UNPACKER_ERRORS);
    dbm->insertCSV(Utils::get_files(Utils::BROKEN_KEY), Utils::BROKEN_KEY);

    dbm->UpdateSignatureIssuingFingerprint();

    dbm->UpdateSignatureIssuingUsername();

    dbm->UpdateIsExpired();

    dbm->UpdateIsRevoked();

    dbm->UpdateIsValid();

    dbm->unlockTables();

    syslog(LOG_NOTICE, "Dump_import is stopping!");

    return hashes;
}


