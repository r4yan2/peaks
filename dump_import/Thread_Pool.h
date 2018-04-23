#include <functional>
#include <vector>
#include <mutex>
#include <condition_variable>
#define TIMEOUT 10

class Thread_Pool {

public:
    Thread_Pool();

    void Infinite_loop_function();
    void Add_Job(std::function<void()> New_Job);
    void Stop_Filling_UP();
    void Start_Filling_UP();

private:
    bool filling_up;
    std::vector<std::function<void()>> queue;
    std::mutex queue_mutex;
    std::condition_variable condition;
};
