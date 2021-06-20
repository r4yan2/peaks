#ifndef STOPPABLE_H
#define STOPPABLE_H
#include <future>
#include <mutex>

namespace peaks{
namespace common{
class Stoppable {
private:
    std::promise<void> exitSignal;
    std::future<void> futureObj;
    std::mutex condition_mutex;
    std::condition_variable condition;
public:
    Stoppable();
    Stoppable(Stoppable && obj);
    Stoppable & operator=(Stoppable && obj);
    virtual void run() = 0;
    void operator()();
    bool stopRequested();
    void stop();
    bool sleep(int);
};

}
}

#endif
