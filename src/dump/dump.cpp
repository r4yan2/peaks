#include "dump.h"
#include <iostream>

namespace peaks{
namespace dump{
namespace Dump{
    int dump(po::variables_map &vm){
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

        openlog("pgp_dump", log_option, LOG_USER);
        setlogmask(log_upto);
        syslog(LOG_NOTICE, "Starting Dump procedure!");
    
        unsigned int nThreads = std::thread::hardware_concurrency() / 2 + 1;
    
        if(vm.count("threads"))
            nThreads = vm["threads"].as<unsigned int>();
        
        syslog(LOG_NOTICE, "Using %d Threads", nThreads);

        const DBSettings db_settings = {
            vm["db_user"].as<std::string>(),
            vm["db_password"].as<std::string>(),
            vm["db_host"].as<std::string>(),
            vm["db_database"].as<std::string>()
        };
        std::shared_ptr<DUMP_DBManager> dbm = std::make_shared<DUMP_DBManager>(db_settings);

        std::string dump_path;
        if (vm.count("outdir")){
            dump_path = vm["outdir"].as<std::string>();
            dbm->set_dump_path(dump_path);
        }else{
            dump_path = dbm->get_dump_path();
        }

        try{
            if (Utils::get_files_number(dump_path) > 0){
                std::cout << "Dump already present, exiting" << std::endl;
                exit(1);
            }
        }catch(boost::filesystem::filesystem_error &e){
            std::cout << "Error when trying to access dump folder, maybe you don't have permissions or it is under a different filesystem (i.e Docker container)\nContinuing but will be unable to prevent errors" << std::endl;
        }
        std::cout << "Dump will be saved in " << dump_path << std::endl;

        std::shared_ptr<Thread_Pool> pool = std::make_shared<Thread_Pool>();
        std::vector<std::thread> pool_vect(nThreads);
        for (unsigned int i = 0; i < nThreads; i++)
            pool_vect[i] = std::thread([=] { pool->Infinite_loop_function(); });
        for (unsigned int i = Utils::CERTIFICATE; i <= Utils::USERID; i++){
            std::shared_ptr<Job> j;
            if (vm.count("outdir"))
                j = std::make_shared<Job>([=] { (std::make_unique<DUMP_DBManager>(dbm.get()))->dumplocalCSV(i); });
            else
                j = std::make_shared<Job>([=] { (std::make_unique<DUMP_DBManager>(dbm.get()))->dumpCSV(i); });
            pool->Add_Job(j);
        }
        
        pool->Stop_Filling_UP();
    
        for (auto &th: pool_vect){
            while (!th.joinable()){}
            th.join();
        }
        
        syslog(LOG_NOTICE, "Dumping terminated!");
        return 0;
    }
}
}
}
