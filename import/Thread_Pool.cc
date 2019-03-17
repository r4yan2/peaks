#include <thread>
#include "Thread_Pool.h"

using namespace std;

Thread_Pool::Thread_Pool(){
    Start_Filling_UP();
};

void Thread_Pool::Infinite_loop_function() {


    while (filling_up || !queue.empty()) {
        function<void()> Job;
        {
            unique_lock <mutex> lock(queue_mutex);

            //condition.wait(lock, [&] { return !queue.empty(); });
            if(!condition.wait_for(lock, chrono::milliseconds(10), [&] { return !queue.empty(); })){continue;};
            Job = queue.front();
            queue.erase(queue.begin());
        }
        Job();
    }
};

void Thread_Pool::Add_Job(function<void()> New_Job) {
    {
        unique_lock <mutex> lock(queue_mutex);
        queue.push_back(New_Job);
    }
    condition.notify_one();
};

void Thread_Pool::Stop_Filling_UP(){
    filling_up = false;
}

void Thread_Pool::Start_Filling_UP(){
    filling_up = true;
}