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
    Utils::create_folders(settings.csv_folder);
    Utils::create_folders(settings.error_folder);

    Import::unpack_string_th(db_settings, keys);

    dbm->lockTables();
    vector<string> hashes = get_hashes(Utils::get_files(settings.csv_folder, Utils::CERTIFICATE));
    dbm->insertCSV(Utils::get_files(settings.csv_folder, Utils::CERTIFICATE), Utils::CERTIFICATE);
    dbm->unlockTables();

    Utils::remove_directory_content(settings.csv_folder);
    return hashes;
}

Importer::Importer(){};
Importer::~Importer(){};

// PEAKS_DB_MAIN
void Importer::import(po::variables_map &vm) {

    std::cout << Utils::getCurrentTime() << "Starting unpacker" << std::endl;

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

    if(vm.count("fastimport"))
        selection = Utils::CERTIFICATE;
    else if (vm.count("selection"))
        selection = vm["selection"].as<int>();

    if(vm.count("threads"))
        nThreads = vm["threads"].as<unsigned int>();
    
    std::cout << "Threads: " << nThreads << std::endl;

    settings = {
        vm["import_tmp_folder"].as<std::string>(),
        vm["import_error_folder"].as<std::string>()
    };

    Utils::create_folders(settings.csv_folder);
    Utils::create_folders(settings.error_folder);

    db_settings = {
        vm["db_host"].as<std::string>(),
        vm["db_user"].as<std::string>(),
        vm["db_password"].as<std::string>(),
        vm["db_database"].as<std::string>(),
        vm["import_tmp_folder"].as<std::string>(),
        vm["import_error_folder"].as<std::string>()
    };

    dbm = std::make_shared<IMPORT_DBManager>(db_settings);

    if (!(vm.count("import-only"))){
        boost::filesystem::path path = vm["default_dump_path"].as<std::string>();
        if(vm.count("path"))
            path = vm["path"].as<boost::filesystem::path>();
        else
            std::cout << "No custom path selected" << std::endl;
        
        std::cout << "Searching for certificates in: " << path << std::endl;
    
        std::vector<std::string> files;
        try {
            files = Utils::get_dump_files(path);
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
    
        if(vm.count("keys"))
            key_per_thread = vm["keys"].as<unsigned int>();
        else
            key_per_thread = 1 + ((files.size() - 1)/nThreads); 
        
        std::cout << "Key per Thread: " << key_per_thread << std::endl;

        generate_csv(files, path, nThreads, key_per_thread, vm.count("fastimport"));
    }
    if (!(vm.count("csv-only")))
        import_csv(selection);
    if (vm.count("noclean") == 0){
        std::cout << Utils::getCurrentTime() << "Cleaning temporary folder." << std::endl;
        Utils::remove_directory_content(settings.csv_folder);
    }else{
        std::cout << Utils::getCurrentTime() << "Not removing temporary csv fileiles as user request." << std::endl;
    }
    syslog(LOG_NOTICE, "Dump_import is stopping!");

}

void Importer::generate_csv(std::vector<std::string> files, boost::filesystem::path &path, unsigned int nThreads, unsigned int key_per_thread, int fastimport){
    std::cout << Utils::getCurrentTime() << "Starting dump read" << std::endl;

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
    std::cout << Utils::getCurrentTime() << "Writing dumped packet in DB:" << std::endl;

    dbm->lockTables();
    if (selection == -1){
        for (unsigned int i= Utils::CERTIFICATE; i<= Utils::BROKEN_KEY; i++){
            std::cout << Utils::getCurrentTime() << "\tInserting ";
            std::string s = Utils::FILENAME.at(i); 
            std::cout << s.substr(1, s.size()-5) << std::endl;
            dbm->insertCSV(Utils::get_files(settings.csv_folder, i), i);
        }
        std::cout << Utils::getCurrentTime() << "\tUpdating issuing fingerprint in Signatures" << std::endl;
        dbm->UpdateSignatureIssuingFingerprint();
        std::cout << Utils::getCurrentTime() << "\tSetting revoked flag" << std::endl;
        dbm->UpdateIsRevoked();
    }
    else{
        std::cout << Utils::getCurrentTime() << "\tInserting ";
        std::string s = Utils::FILENAME.at(selection); 
        std::cout << s.substr(1, s.size()-5) << std::endl;
        dbm->insertCSV(Utils::get_files(settings.csv_folder, selection), selection);

    }

    dbm->unlockTables();

}


