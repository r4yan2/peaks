#include <ios>
#include <thread>
#include "Thread_Pool.h"
#include <iostream>

using namespace std;

namespace peaks{
namespace common{
Thread_Pool::Thread_Pool():
    filling_up(true)
{}

void Thread_Pool::Infinite_loop_function() {

    while (true) {
        std::shared_ptr<Job> job = Request_Job();
        if (job == nullptr){
            break;
        }
        job->execute();
    }
}

void Thread_Pool::Add_Job(const std::function<void ()> & f) {
    {
        std::lock_guard <mutex> lock(queue_mutex);
        queue.push_back(std::make_shared<Job>(f));
        condition.notify_one();
    }
}

void Thread_Pool::Add_Job(const std::shared_ptr<Job> & new_job) {
    {
        std::lock_guard <mutex> lock(queue_mutex);
        queue.push_back(new_job);
        condition.notify_one();
    }
}

void Thread_Pool::Add_Jobs(const std::vector<std::shared_ptr<Job>> & new_jobs){
    {
        std::lock_guard <mutex> lock(queue_mutex);
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

bool Thread_Pool::done(){
    unique_lock <mutex> lock(queue_mutex);
    if (filling_up) return false;
    for (auto & j: queue)
        if (!j->done())
            return false;
    return true;
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

Job::Job(std::function<void()> f):
    assignment(f),
    status(Job_Status::FREE)
{}

Job::Job(std::function<void()> f, const std::vector<std::shared_ptr<Job>> & depends):
    assignment(f),
    status(Job_Status::FREE),
    dependencies(depends)
{}

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

template<typename T> SafeQueue<T>::SafeQueue():
	q(),
	m(),
	c()
{}

template<typename T> SafeQueue<T>::~SafeQueue()
{}

template<typename T> T SafeQueue<T>::dequeue()
 {
    std::unique_lock<std::mutex> lock(m);
    while(q.empty())
    {
      // release lock as long as the wait and reaquire it afterwards.
      c.wait(lock);
    }
    T val = q.front();
    q.pop();
    return val;
 }

template<typename T> void SafeQueue<T>::enqueue(T t)
  {
    std::lock_guard<std::mutex> lock(m);
    q.push(t);
    c.notify_one();
  }

SynchronizedFile::SynchronizedFile(const std::string& path, bool append):
    name(path),
	f(path, append?ios_base::app:ios_base::out),
	m()
{}

SynchronizedFile::SynchronizedFile():
    name(),
    f(),
    m()
{}

SynchronizedFile::~SynchronizedFile(){}

void SynchronizedFile::open(const std::string& path, bool append){
	std::lock_guard<std::mutex> lock(m);
    name = path;
    auto mode = ios::in|ios::out;
    if (append)
        mode |= ios::app;
    f = fstream(path, mode);
}

std::size_t SynchronizedFile::write(const std::string& data)
{
	std::lock_guard<std::mutex> lock(m);
    std::size_t pos = f.tellp();
	f << data;
    return pos;
}

std::string SynchronizedFile::get_name(){
    return name;
}

std::size_t SynchronizedFile::size(){
    return f.tellg();
}

}
}
