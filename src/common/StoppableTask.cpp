#include <chrono>
#include "StoppableTask.h"
/*
 * Class that encapsulates promise and future object and
 * provides API to set exit signal for the thread
 */

namespace peaks{
namespace common{
Stoppable::Stoppable():
    futureObj(exitSignal.get_future())
{}

Stoppable::Stoppable(Stoppable && obj): 
    exitSignal(std::move(obj.exitSignal)), 
    futureObj(std::move(obj.futureObj))
    {}

Stoppable& Stoppable::operator=(Stoppable && obj)
{
    exitSignal = std::move(obj.exitSignal);
    futureObj = std::move(obj.futureObj);
    return *this;
}

void Stoppable::operator()()
{
    run();
}
//Checks if thread is requested to stop
bool Stoppable::stopRequested()
{
    return false;
    // checks if value in future object is available
    /*
    if (futureObj.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout)
        return false;
    return true;
    */
}
// Request the thread to stop by setting value in promise object
void Stoppable::stop()
{
    exitSignal.set_value();
    std::lock_guard <std::mutex> lock(condition_mutex);
    condition.notify_all();
}

bool Stoppable::sleep(int sec){
    std::unique_lock <std::mutex> lock(condition_mutex);
    return condition.wait_for(lock, std::chrono::seconds{sec})!=std::cv_status::timeout;
}

}
}
