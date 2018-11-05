#include "dump_import.h"

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

    if(DUMP_Utils::create_folders() == -1){
        exit(-1);
    }

    shared_ptr<DUMPIMPORT_DBManager> dbm = make_shared<DUMPIMPORT_DBManager>();

    Dumpimport::unpack_string_th(keys);


    dbm->lockTables();
    vector<string> hashes = get_hashes(DUMP_Utils::get_files(DUMP_Utils::CERTIFICATE));
    dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::CERTIFICATE), DUMP_Utils::CERTIFICATE);
    dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::PUBKEY), DUMP_Utils::PUBKEY);
    dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::USERID), DUMP_Utils::USERID);
    dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::USER_ATTRIBUTES), DUMP_Utils::USER_ATTRIBUTES);
    dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::SIGNATURE), DUMP_Utils::SIGNATURE);
    dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::SELF_SIGNATURE), DUMP_Utils::SELF_SIGNATURE);
    dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::UNPACKER_ERRORS), DUMP_Utils::UNPACKER_ERRORS);
    dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::BROKEN_KEY), DUMP_Utils::BROKEN_KEY);

    dbm->UpdateSignatureIssuingFingerprint();

    dbm->UpdateSignatureIssuingUsername();

    dbm->UpdateIsExpired();

    dbm->UpdateIsRevoked();

    dbm->UpdateIsValid();

    dbm->unlockTables();

    syslog(LOG_NOTICE, "Dump_import is stopping!");

    return hashes;
}

// PEAKS_DB_MAIN
void import(po::variables_map &vm) {

    std::cout << DUMP_Utils::getCurrentTime() << "Starting unpacker" << std::endl;

    openlog("pgp_dump_import", LOG_PID, LOG_USER);
    setlogmask (LOG_UPTO (LOG_NOTICE));
    syslog(LOG_NOTICE, "Dump_import is starting up!");
    unsigned int nThreads = std::thread::hardware_concurrency() / 2 + 1;
    unsigned int key_per_thread;
    boost::filesystem::path path = recon_settings.default_dump_path;
    boost::filesystem::path csv_path = recon_settings.tmp_folder_csv;

    if(vm.count("path"))
        path = vm["path"].as<boost::filesystem::path>();
    else
        std::cout << "No custom path selected" << std::endl;
    
    std::cout << "Searching for certificates in: " << path << std::endl;

    std::vector<std::string> files;
    try {
        files = DUMP_Utils::get_dump_files(path);
    }catch (std::exception &e){
        std::cerr << "Unable to read dump folder/files" << std::endl;
        exit(-1);
    }
    if (files.size() == 0){
        std::cout << "Found no key to import! Aborting..." << std::endl;
        exit(0);
    }else{
    std::cout << "Found " << files.size() << " keys to import" << std::endl;
    }

    if(vm.count("threads"))
        nThreads = vm["threads"].as<unsigned int>();
    
    std::cout << "Threads: " << nThreads << std::endl;

    if(vm.count("keys"))
        key_per_thread = vm["keys"].as<unsigned int>();
    else
        key_per_thread = 1 + ((files.size() - 1)/nThreads); 
    
    std::cout << "Key per Thread: " << key_per_thread << std::endl;


    if(DUMP_Utils::create_folders() == -1){
        std::cerr << "Unable to create temp folder" << std::endl;
        exit(-1);
    }

    std::shared_ptr<DUMPIMPORT_DBManager> dbm = std::make_shared<DUMPIMPORT_DBManager>();

    if (!(vm.count("import-only")))
        generate_csv(files, path, nThreads, key_per_thread, vm.count("fastimport"));
    if (!(vm.count("csv-only")))
        import_csv(dbm, vm.count("fastimport"));
    if (vm.count("noclean") == 0){
        std::cout << DUMP_Utils::getCurrentTime() << "Cleaning temporary folder." << std::endl;
        remove_directory_content(recon_settings.tmp_folder_csv);
    }else{
        std::cout << DUMP_Utils::getCurrentTime() << "Not removing temporary csv fileiles as user request." << std::endl;
    }

    syslog(LOG_NOTICE, "Dump_import is stopping!");

}

void generate_csv(std::vector<std::string> files, boost::filesystem::path &path, unsigned int nThreads, unsigned int key_per_thread, int fastimport){
    std::cout << DUMP_Utils::getCurrentTime() << "Starting dump read" << std::endl;

    std::shared_ptr<Thread_Pool> pool = std::make_shared<Thread_Pool>();
    std::vector<std::thread> pool_vect(nThreads);

    for (unsigned int i = 0; i < nThreads; i++){
        pool_vect[i] = std::thread([=] { pool->Infinite_loop_function(); });
    }

    for (unsigned int i = 0; i < files.size();){
        std::vector<std::string> dump_file_tmp;
        for (unsigned int j = 0; i < files.size() && j < key_per_thread; j++, i++){
            dump_file_tmp.push_back(files[i]);
        }
        pool->Add_Job([=] { return Dumpimport::unpack_dump_th(dump_file_tmp, fastimport); });
    }

    pool->Stop_Filling_UP();

    for (auto &th: pool_vect){
        while (!th.joinable()){}
        th.join();
    }
}

void import_csv(std::shared_ptr<DUMPIMPORT_DBManager> dbm, int fastimport){

    std::cout << DUMP_Utils::getCurrentTime() << "Writing dumped packet in DB:" << std::endl;

    dbm->lockTables();
    std::cout << DUMP_Utils::getCurrentTime() << "\tInserting Certificates" << std::endl;
    dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::CERTIFICATE), DUMP_Utils::CERTIFICATE);
    if (fastimport == 0){
        std::cout << DUMP_Utils::getCurrentTime() << "\tInserting Pubkeys" << std::endl;
        dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::PUBKEY), DUMP_Utils::PUBKEY);
        std::cout << DUMP_Utils::getCurrentTime() << "\tInserting UserID" << std::endl;
        dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::USERID), DUMP_Utils::USERID);
        std::cout << DUMP_Utils::getCurrentTime() << "\tInserting User Attributes" << std::endl;
        dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::USER_ATTRIBUTES), DUMP_Utils::USER_ATTRIBUTES);
        std::cout << DUMP_Utils::getCurrentTime() << "\tInserting Signatures" << std::endl;
        dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::SIGNATURE), DUMP_Utils::SIGNATURE);
        std::cout << DUMP_Utils::getCurrentTime() << "\tInserting SelfSignatures" << std::endl;
        dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::SELF_SIGNATURE), DUMP_Utils::SELF_SIGNATURE);
        std::cout << DUMP_Utils::getCurrentTime() << "\tInserting Unpacker Errors" << std::endl;
        dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::UNPACKER_ERRORS), DUMP_Utils::UNPACKER_ERRORS);
        std::cout << DUMP_Utils::getCurrentTime() << "\tInserting Broken Keys" << std::endl;
        dbm->insertCSV(DUMP_Utils::get_files(DUMP_Utils::BROKEN_KEY), DUMP_Utils::BROKEN_KEY);

        std::cout << DUMP_Utils::getCurrentTime() << "Updating DB fields:" << std::endl;

        std::cout << DUMP_Utils::getCurrentTime() << "\tUpdating issuing fingerprint in Signatures" << std::endl;
        dbm->UpdateSignatureIssuingFingerprint();

        std::cout << DUMP_Utils::getCurrentTime() << "\tUpdating issuing username in Signatures" << std::endl;
        dbm->UpdateSignatureIssuingUsername();

        std::cout << DUMP_Utils::getCurrentTime() << "\tSetting expired flag" << std::endl;
        dbm->UpdateIsExpired();

        std::cout << DUMP_Utils::getCurrentTime() << "\tSetting revoked flag" << std::endl;
        dbm->UpdateIsRevoked();

        std::cout << DUMP_Utils::getCurrentTime() << "\tSetting valid flag" << std::endl;
        dbm->UpdateIsValid();
    }

    dbm->unlockTables();

}

void remove_directory_content(const std::string &foldername)
{
    // These are data types defined in the "dirent" header
    DIR *theFolder = opendir(foldername.c_str());
    struct dirent *next_file;
    char filepath[256];

    while ( (next_file = readdir(theFolder)) != NULL )
    {
        // build the path for each file in the folder
        sprintf(filepath, "%s/%s", foldername.c_str(), next_file->d_name);
        remove(filepath);
    }
    closedir(theFolder);
}
