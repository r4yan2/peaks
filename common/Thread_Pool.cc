#include <thread>
#include "Thread_Pool.h"

using namespace std;

Thread_Pool::Thread_Pool(){
    Start_Filling_UP();
};

void Thread_Pool::Infinite_loop_function() {

    while (true) {
        std::shared_ptr<Job> job = Request_Job();
        if (job == nullptr){
            break;
        }
        job->execute();
    }
};

void Thread_Pool::Add_Job(std::shared_ptr<Job> new_job) {
    {
        unique_lock <mutex> lock(queue_mutex);
        queue.push_back(new_job);
        condition.notify_one();
    }
};

void Thread_Pool::Add_Jobs(std::vector<std::shared_ptr<Job>> new_jobs){
    {
        unique_lock <mutex> lock(queue_mutex);
        queue.insert(queue.end(), new_jobs.begin(), new_jobs.end());
        condition.notify_all();
    }
}

void Thread_Pool::Stop_Filling_UP(){
    filling_up = false;
}

void Thread_Pool::Start_Filling_UP(){
    filling_up = true;
}

std::shared_ptr<Job> Thread_Pool::Request_Job(){
    unique_lock <mutex> lock(queue_mutex);
    while(true){
        bool all_done = true;
        for (auto & j: queue){
            if (!j->free())
                continue;
            all_done = false;
            bool dep_ok = true;
            for (auto & jp: j->get_dependencies())
                if (!jp->done())
                    dep_ok = false;
            if (dep_ok){
                j->set_assigned();
                return j;
            }
        }
        if (all_done && !filling_up)
            return nullptr;
        condition.wait_for(lock, std::chrono::seconds{TIMEOUT});
    }
}

Job::Job(std::function<void()> f){
    status = Job_Status::FREE;
    assignment = f;
    dependencies.clear();
}

Job::Job(std::function<void()> f, const std::vector<std::shared_ptr<Job>> & depends){
    status = Job_Status::FREE;
    assignment = f;
    for (auto & dep: depends)
        dependencies.push_back(dep);
}

Job::~Job(){}

void Job::execute(){
    assignment();
    status = Job_Status::DONE;
}

bool Job::done(){
    return status == Job_Status::DONE;
}

bool Job::assigned(){
    return status == Job_Status::ASSIGNED;
}

bool Job::free(){
    return status == Job_Status::FREE;
}

void Job::set_assigned(){
    status = Job_Status::ASSIGNED;
}

void Job::set_done(){
    status = Job_Status::DONE;
}

std::vector<std::shared_ptr<Job>> Job::get_dependencies(){
    return dependencies;
}
