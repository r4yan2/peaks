#include <ios>
#include <stdexcept>
#include <thread>
#include "Thread_Pool.h"
#include <iostream>
#include <assert.h>
using namespace std;

namespace peaks{
namespace common{

Thread_Pool::Thread_Pool(){}

Thread_Pool::Thread_Pool(const unsigned int &size):
    state(Pool_Status::FILLING),
    pool_vect(size)
{
    for (unsigned int i = 0; i < size; i++)
        pool_vect[i] = std::thread([=] { Infinite_loop_function(); });
}

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
        for (size_t i=0; i<new_jobs.size(); i++) condition.notify_one();
    }
}

void Thread_Pool::terminate(){
    state = Pool_Status::DONE;
    condition.notify_all();
    for (auto &th: pool_vect){
        th.join();
    }
    assert(done());
}

bool Thread_Pool::done(){
    for (auto & j: queue)
        if (!j->done())
            return false;
    return true;
}

std::shared_ptr<Job> Thread_Pool::Request_Job(){
    while(true){
        {
            std::lock_guard <mutex> lock(queue_mutex);
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
            if (all_done && state == Pool_Status::DONE) {
                return nullptr;
            }
        }
    	std::this_thread::sleep_for(std::chrono::milliseconds{500});
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
    try{
        assignment();
    }catch(std::exception &e){
        std::cerr << e.what() << std::endl;
    }
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

SynchronizedOutFile::SynchronizedOutFile(const std::string& path, bool append):
    name(path),
	f(path, append?(ios::app):(ios::out)),
    pos(f.tellp()),
	m()
{}

SynchronizedOutFile::SynchronizedOutFile():
    name(),
    f(),
    pos(0),
    m()
{}

SynchronizedOutFile::~SynchronizedOutFile(){
    close();
}

void SynchronizedOutFile::open(const std::string& path, bool append){
	std::lock_guard<std::mutex> lock(m);
    name = path;
    auto mode = append ? ios::app : ios::out;
    f = fstream(path, mode);
    pos = f.tellp();
}

void SynchronizedOutFile::close(){
	std::lock_guard<std::mutex> lock(m);
    if (f.is_open())
        f.close();
}

void SynchronizedOutFile::flush(){
	std::lock_guard<std::mutex> lock(m);
    if (f.is_open())
        f.flush();
}

std::size_t SynchronizedOutFile::write(const std::string& data, bool flush)
{
	std::lock_guard<std::mutex> lock(m);
    if (!f.is_open())
        throw std::runtime_error("File is not open");
    std::size_t orig = pos;
    pos += data.size();
	f.write(data.c_str(), data.size());
    if (!f)
        throw std::runtime_error("Failed writing");
    if (flush) f.flush();
    return orig;
}

std::string SynchronizedOutFile::get_name(){
    return name;
}

std::size_t SynchronizedOutFile::size(){
	std::lock_guard<std::mutex> lock(m);
    return pos;
}

}
}
