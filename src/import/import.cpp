#include "import.h"
#include "common/utils.h"
#include <boost/program_options/variables_map.hpp>
#include <functional>
#include <common/config.h>

using namespace std;
using namespace std::chrono_literals;

namespace peaks{
namespace import{

// PEAKS_DB_MAIN
void import() {
    syslog(LOG_NOTICE, "Dump_import is starting up!");
    if (CONTEXT.has("init")){
        std::string filename = CONTEXT.get<std::string>("init", "schema.sql");
        std::ifstream cFile(filename);
        if (!cFile.is_open()){
            std::cout << "Could not find init file for DB" << std::endl;
            exit(0);
        }
        std::make_shared<DBManager>()->init_database(filename);
        std::this_thread::sleep_for(std::chrono::milliseconds(2000)); // wait for mysql to initialize DB
    }

    std::shared_ptr<IMPORT_DBManager> dbm;
    try{
        dbm = std::make_shared<IMPORT_DBManager>();
        Utils::create_folders(CONTEXT.dbsettings.tmp_folder);
        Utils::create_folders(CONTEXT.dbsettings.error_folder);
    }catch(std::exception &e){
        std::cout << "Unable to connect to the database: "<< e.what() << std::endl;
        exit(0);
    }
    std::string status = "";
    dbm->get_from_cache("import_status", status);
    if (status == "ready"){
        if (!(CONTEXT.get<bool>("csv-only")))
            import_csv(dbm);
        dbm->store_in_cache("import_status", "done");
    }
        
    int nThreads = CONTEXT.get<int>("threads", std::thread::hardware_concurrency() / 2 + 1);
    size_t key_per_thread;

    std::cout << "Threads: " << nThreads << std::endl;

    if (!(CONTEXT.get<bool>("import-only"))){
        boost::filesystem::path path = CONTEXT.get<std::string>("path", CONTEXT.get<std::string>("default_dump_path"));
        
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
    
        key_per_thread = 1 + ((files.size() - 1)/nThreads); 
        
        std::cout << "Keyfile per Thread: " << key_per_thread << std::endl;

        generate_csv(dbm, files, path, nThreads, key_per_thread, CONTEXT.get<bool>("fastimport"));
    }
    if (!CONTEXT.get<bool>("csv-only")){
        import_csv(dbm);
    }
    if (CONTEXT.get<bool>("noclean")){
        std::cout << Utils::getCurrentTime() << "Not removing temporary csv file as user request." << std::endl;
    }
    syslog(LOG_NOTICE, "Dump_import is stopping!");

}

void generate_csv(std::shared_ptr<IMPORT_DBManager> dbm, std::vector<std::string> files, boost::filesystem::path &path, int nThreads, size_t key_per_thread, int fastimport){
    std::cout << Utils::getCurrentTime() << "Starting dump read" << std::endl;

    dbm->openCSVFiles();
    std::shared_ptr<Thread_Pool> pool = std::make_shared<Thread_Pool>(nThreads);

    for (size_t i = 0; i < files.size();){
        std::vector<std::string> dump_file_tmp;
        for (size_t j = 0; i < files.size() && j < key_per_thread; j++, i++){
            dump_file_tmp.push_back(files[i]);
        }
        std::function<void ()> f = std::bind(Import::unpack_dump_th, dbm, dump_file_tmp, fastimport);
        pool->Add_Job(f);
    }

    pool->terminate();
}

void import_csv(std::shared_ptr<IMPORT_DBManager> dbm){

    std::cout << Utils::getCurrentTime() << "Writing in DB" << std::endl;
    std::cout << "Drop index" << std::endl;
    dbm->drop_index_gpg_keyserver();
    dbm->store_in_cache("import_status", "ready");
    dbm->insertCSV();
    dbm->store_in_cache("import_status", "done");
    std::cout << "Rebuilding index" << std::endl;
    dbm->build_index_gpg_keyserver();
}

}
}

