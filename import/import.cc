#include "import.h"

using namespace std;
using namespace std::chrono_literals;

ReconImporter::ReconImporter(){
}
ReconImporter::ReconImporter(po::variables_map &vm){
    settings = {
        vm["import_tmp_folder"].as<std::string>(),
        vm["import_error_folder"].as<std::string>(),
    };
    db_settings = {
        vm["db_host"].as<std::string>(),
        vm["db_user"].as<std::string>(),
        vm["db_password"].as<std::string>(),
        vm["db_database"].as<std::string>(),
        vm["import_tmp_folder"].as<std::string>(),
        vm["import_error_folder"].as<std::string>(),
    };
}

ReconImporter::~ReconImporter(){}

vector<string> ReconImporter::get_hashes(const vector<string> &files){
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

vector<string> ReconImporter::import(vector<string> keys){

    dbm = make_shared<IMPORT_DBManager>(db_settings);
    dbm->init_database_connection();
    IMPORT_Utils::create_folder(settings.csv_folder);
    IMPORT_Utils::create_folder(settings.error_folder);

    Import::unpack_string_th(db_settings, keys);

    dbm->lockTables();
    vector<string> hashes = get_hashes(IMPORT_Utils::get_files(settings.csv_folder, IMPORT_Utils::CERTIFICATE));
    dbm->insertCSV(IMPORT_Utils::get_files(settings.csv_folder, IMPORT_Utils::CERTIFICATE), IMPORT_Utils::CERTIFICATE);
    dbm->unlockTables();

    IMPORT_Utils::remove_directory_content(settings.csv_folder);
    return hashes;
}

Importer::Importer(){};
Importer::~Importer(){};

// PEAKS_DB_MAIN
void Importer::import(po::variables_map &vm) {

    std::cout << IMPORT_Utils::getCurrentTime() << "Starting unpacker" << std::endl;

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

    openlog("pgp_import", log_option, LOG_USER);
    setlogmask(log_upto);
    syslog(LOG_NOTICE, "Dump_import is starting up!");
    unsigned int nThreads = std::thread::hardware_concurrency() / 2 + 1;
    unsigned int key_per_thread;
    int selection = -1;
    boost::filesystem::path path = vm["default_dump_path"].as<std::string>();

    if(vm.count("fastimport"))
        selection = 0;
    else if (vm.count("selection"))
        selection = vm["selection"].as<int>();

    if(vm.count("path"))
        path = vm["path"].as<boost::filesystem::path>();
    else
        std::cout << "No custom path selected" << std::endl;
    
    std::cout << "Searching for certificates in: " << path << std::endl;

    std::vector<std::string> files;
    try {
        files = IMPORT_Utils::get_dump_files(path);
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

    settings = {
        vm["import_tmp_folder"].as<std::string>(),
        vm["import_error_folder"].as<std::string>()
    };

    IMPORT_Utils::create_folder(settings.csv_folder);
    IMPORT_Utils::create_folder(settings.error_folder);

    db_settings = {
        vm["db_host"].as<std::string>(),
        vm["db_user"].as<std::string>(),
        vm["db_password"].as<std::string>(),
        vm["db_database"].as<std::string>(),
        vm["import_tmp_folder"].as<std::string>(),
        vm["import_error_folder"].as<std::string>()
    };

    dbm = std::make_shared<IMPORT_DBManager>(db_settings);

    if (!(vm.count("import-only")))
        generate_csv(files, path, nThreads, key_per_thread, vm.count("fastimport"));
    if (!(vm.count("csv-only")))
        import_csv(selection);
    if (vm.count("noclean") == 0){
        std::cout << IMPORT_Utils::getCurrentTime() << "Cleaning temporary folder." << std::endl;
        IMPORT_Utils::remove_directory_content(settings.csv_folder);
    }else{
        std::cout << IMPORT_Utils::getCurrentTime() << "Not removing temporary csv fileiles as user request." << std::endl;
    }
    syslog(LOG_NOTICE, "Dump_import is stopping!");

}

void Importer::generate_csv(std::vector<std::string> files, boost::filesystem::path &path, unsigned int nThreads, unsigned int key_per_thread, int fastimport){
    std::cout << IMPORT_Utils::getCurrentTime() << "Starting dump read" << std::endl;

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
        pool->Add_Job(std::make_shared<Job>([=] { return Import::unpack_dump_th(db_settings, dump_file_tmp, fastimport); }));
    }

    pool->Stop_Filling_UP();

    for (auto &th: pool_vect){
        while (!th.joinable()){}
        th.join();
    }
}

void Importer::import_csv(int selection){

    dbm->init_database_connection();
    std::cout << IMPORT_Utils::getCurrentTime() << "Writing dumped packet in DB:" << std::endl;

    dbm->lockTables();
    switch(selection){
        default:{}
        case 0:{
        std::cout << IMPORT_Utils::getCurrentTime() << "\tInserting Certificates" << std::endl;
        dbm->insertCSV(IMPORT_Utils::get_files(settings.csv_folder, IMPORT_Utils::CERTIFICATE), IMPORT_Utils::CERTIFICATE);
        if (selection == 0) break;
           }
        case 1:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tInserting Pubkeys" << std::endl;
            dbm->insertCSV(IMPORT_Utils::get_files(settings.csv_folder, IMPORT_Utils::PUBKEY), IMPORT_Utils::PUBKEY);
            if (selection == 1) break;
               }
        case 2:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tInserting UserID" << std::endl;
            dbm->insertCSV(IMPORT_Utils::get_files(settings.csv_folder, IMPORT_Utils::USERID), IMPORT_Utils::USERID);
            if (selection == 2) break;
               }
        case 3:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tInserting User Attributes" << std::endl;
            dbm->insertCSV(IMPORT_Utils::get_files(settings.csv_folder, IMPORT_Utils::USER_ATTRIBUTES), IMPORT_Utils::USER_ATTRIBUTES);
            if (selection == 3) break;
               }
            case 4:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tInserting Signatures" << std::endl;
            dbm->insertCSV(IMPORT_Utils::get_files(settings.csv_folder, IMPORT_Utils::SIGNATURE), IMPORT_Utils::SIGNATURE);
            if (selection == 4) break;
               }
            case 5:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tInserting SelfSignatures" << std::endl;
            dbm->insertCSV(IMPORT_Utils::get_files(settings.csv_folder, IMPORT_Utils::SELF_SIGNATURE), IMPORT_Utils::SELF_SIGNATURE);
            if (selection == 5) break;
               }
            case 6:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tInserting Unpacker Errors" << std::endl;
            dbm->insertCSV(IMPORT_Utils::get_files(settings.csv_folder, IMPORT_Utils::UNPACKER_ERRORS), IMPORT_Utils::UNPACKER_ERRORS);
            if (selection == 6) break;
                  }
            case 7:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tInserting Broken Keys" << std::endl;
            dbm->insertCSV(IMPORT_Utils::get_files(settings.csv_folder, IMPORT_Utils::BROKEN_KEY), IMPORT_Utils::BROKEN_KEY);
            if (selection == 7) break;
                  }
            case 8:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tUpdating issuing fingerprint in Signatures" << std::endl;
            dbm->UpdateSignatureIssuingFingerprint();
            if (selection == 8) break;
                }
            case 9:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tUpdating issuing username in Signatures" << std::endl;
            dbm->UpdateSignatureIssuingUsername();
            if (selection == 9) break;
                }
            case 10:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tSetting expired flag" << std::endl;
            dbm->UpdateIsExpired();
            if (selection == 10) break;
                }
            case 11:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tSetting revoked flag" << std::endl;
            dbm->UpdateIsRevoked();
            if (selection == 11) break;
                }
            case 12:{
            std::cout << IMPORT_Utils::getCurrentTime() << "\tSetting valid flag" << std::endl;
            dbm->UpdateIsValid();
            if (selection == 12) break;
                }
    }

    dbm->unlockTables();

}


