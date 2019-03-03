#ifndef UNPACKER_THREAD_POOL_H
#define UNPACKER_THREAD_POOL_H

#include <functional>
#include <vector>
#include <mutex>
#include <condition_variable>
#define TIMEOUT 10

/** @brief Possible status for a job
 * This enum holds the possible status for a Job
 * DONE mean the jobs has been completed
 * ASSIGNED mean the jobs has been assigned to a worker and its currently in processing
 * FREE mean the jobs is yet to be assigned
 */
enum class Job_Status{
    DONE,
    ASSIGNED,
    FREE
};

/** @brief Job for a worker (thread)
 * A job is a task which needs to be executed 
 * by one of the dispathed workers (threads) in the pool.
 * Each job may have dependencies which need to be completed
 * before taking the job
 */
class Job {

public:
    /** @brief Constructor for a job
     * The basic constructor take only the function 
     * which needs to be computed by the worker.
     * The job begin in status FREE
     * @param f function to compute
     */
    Job(std::function<void()> f);
    
    /** @brief Constructor for a job with dependencies
     * The dependencies may be expressed as a vector of pointer
     * to other jobs which needs to be completed
     * before this job can be started.
     * The job begin in status FREE
     * @param f function to compute
     * @param depends list of dependencies
     */
    Job(std::function<void()> f, const std::vector<std::shared_ptr<Job>> & depends);

    /** @brief default destructor
     */
    ~Job();
    
    /** @brief start the work
     * execute the stored procedure
     */
   void execute();

   /** @brief query if done
    */
   bool done();

   /** @brief query if assigned
    */
   bool assigned();

   /** @brief query if free
    */
   bool free();

   /** @brief get dependencies
    */
   std::vector<std::shared_ptr<Job>> get_dependencies();

   /** @brief set assigned status
    */
   void set_assigned();

   /** @brief set done status
    */
   void set_done();


private:
   std::function<void ()> assignment;
   Job_Status status;
   std::vector<std::shared_ptr<Job>> dependencies;
};

/** @brief Thread pool manager class
 * Manager of the workers (threads) and relative Jobs.
 * Each thread run the main loop (Infinite_loop_function)
 * and when it has nothing to do ask for
 * a Job. If there is a job it performs it
 * otherwise it wait. If there are no more job the worker exit
 */
class Unpacker_Thread_Pool {

public:

    /** @brief default constructor
     */
    Unpacker_Thread_Pool();
    
    /** @brief main loop of the worker
     */
    void Infinite_loop_function();

    /** @brief Add a job to the pool
     * @param new_job Job to be added
     */
    void Add_Job(std::shared_ptr<Job> new_job);

    /** @brief Add multiple jobs to the pool
     * @param new_jobs vector of jobs to be added
     */
    void Add_Jobs(std::vector<std::shared_ptr<Job>> new_jobs);

    /** @brief Signal that no more jobs will be added
     */
    void Stop_Filling_UP();

    /** @brief Signal that jobs are being added
     */
    void Start_Filling_UP();

    /** @brief Used by the worker to request something to do
     * @return Job to perform
     */
    std::shared_ptr<Job> Request_Job();

private:
    bool filling_up;
    std::vector<std::shared_ptr<Job>> queue;
    std::vector<int> checkout;
    std::mutex queue_mutex;
    std::mutex checkout_mutex;
    std::condition_variable condition;
};

#endif
