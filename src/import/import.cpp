#include "import.h"
#include <boost/program_options/variables_map.hpp>
#include <functional>
#include <common/config.h>

using namespace std;
using namespace std::chrono_literals;

namespace peaks{
namespace import{
Importer::Importer(){};
Importer::~Importer(){};

// PEAKS_DB_MAIN
void Importer::import() {

    std::cout << Utils::getCurrentTime() << "Starting unpacker" << std::endl;

    int log_option;
    int log_upto;

    po::variables_map vm = CONTEXT.vm;

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

    selection = Utils::CERTIFICATE;

    if(vm.count("threads"))
        nThreads = vm["threads"].as<unsigned int>();
    
    std::cout << "Threads: " << nThreads << std::endl;

    Utils::create_folders(CONTEXT.dbsettings.tmp_folder);
    Utils::create_folders(CONTEXT.dbsettings.error_folder);

    std::string filename;
    auto it = CONTEXT.vm.find("init");
    if (it != CONTEXT.vm.end()){
        filename = it->second.as<std::string>();
        if (filename != "") {
            std::make_shared<DBManager>()->init_database(filename);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // wait for mysql to initialize DB
        }
    }

    try{
        dbm = std::make_shared<IMPORT_DBManager>();
    }catch(std::exception &e){
        std::cout << "Unable to connect to the database: "<< e.what() << std::endl;
        exit(0);
    }

    if (CONTEXT.quitting) return;
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
        
        std::cout << "Keyfile per Thread: " << key_per_thread << std::endl;

        generate_csv(files, path, nThreads, key_per_thread, vm.count("fastimport"));
    }
    if (CONTEXT.quitting) return;
    if (!(vm.count("csv-only"))){
        std::cout << "Drop index" << std::endl;
        dbm->drop_index_gpg_keyserver();
        import_csv(nThreads, selection);
        std::cout << "Rebuilding index" << std::endl;
        dbm->build_index_gpg_keyserver();
    }
    if (vm.count("noclean") == 0){
        std::cout << Utils::getCurrentTime() << "Cleaning temporary folder." << std::endl;
        Utils::remove_directory_content(CONTEXT.dbsettings.tmp_folder);
    }else{
        std::cout << Utils::getCurrentTime() << "Not removing temporary csv file as user request." << std::endl;
    }
    syslog(LOG_NOTICE, "Dump_import is stopping!");

}

void Importer::generate_csv(std::vector<std::string> files, boost::filesystem::path &path, unsigned int nThreads, unsigned int key_per_thread, int fastimport){
    std::cout << Utils::getCurrentTime() << "Starting dump read" << std::endl;

    dbm->openCSVFiles();
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
        std::function<void ()> f = std::bind(Import::unpack_dump_th, dbm, dump_file_tmp, fastimport);
        pool->Add_Job(f);
    }

    pool->Stop_Filling_UP();

    for (auto &th: pool_vect){
        while (!th.joinable()){}
        th.join();
    }
}

void Importer::import_csv(unsigned int nThreads, int selection){

    std::cout << Utils::getCurrentTime() << "Writing dumped packet in DB:" << std::endl;

    std::shared_ptr<Thread_Pool> pool = std::make_shared<Thread_Pool>();
    std::vector<std::function<void ()>> jobs;
    
    std::cout << Utils::getCurrentTime() << "\tInserting ";
    std::string s = Utils::FILENAME.at(selection); 
    std::cout << s.substr(0, s.size()-4) << std::endl;
    for (const std::string & filename: Utils::get_files(CONTEXT.dbsettings.tmp_folder, selection)){
        jobs.push_back(std::bind(Import::insert_csv, dbm, filename, selection));
    }

    //size_t nJobs = jobs.size();
    //std::vector<std::thread> pool_vect(nThreads > nJobs ? nJobs : nThreads);
    std::vector<std::thread> pool_vect(1);

    for (unsigned int i = 0; i < pool_vect.size(); i++){
        pool_vect[i] = std::thread([=] { pool->Infinite_loop_function(); });
    }
    for (const auto &j: jobs)
        pool->Add_Job(j);
    pool->Stop_Filling_UP();

    while(1){
        if (pool->done()){
            for (auto &th: pool_vect)
                if (th.joinable())
                    th.join();
            break;
        }
        // DB connector is synchronous
        if (CONTEXT.quitting){
            std::terminate(); //abrupt chaos
        }
    }
}

}
}

