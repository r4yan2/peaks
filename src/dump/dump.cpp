#include "dump.h"
#include <iostream>
#include <common/config.h>

namespace peaks{
namespace dump{
    int dump(){
        unsigned int nThreads = CONTEXT.get<int>("threads", 1);
    
        syslog(LOG_NOTICE, "Using %d Threads", nThreads);

        std::shared_ptr<DUMP_DBManager> dbm = std::make_shared<DUMP_DBManager>();

        std::string dump_path = CONTEXT.get<std::string>("outdir", dbm->get_dump_path());

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
            std::shared_ptr<Job> j = std::make_shared<Job>([=] { dbm->dumpCSV(i); });;
            //if (vm.count("outdir"))
            //    j = std::make_shared<Job>([=] { dbm->dumplocalCSV(i); });
            //else
            //    j = std::make_shared<Job>([=] { dbm->dumpCSV(i); });
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
