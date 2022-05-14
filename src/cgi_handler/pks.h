#ifndef PEAKS_PKS_H_
#define PEAKS_PKS_H_

#include <cppcms/service.h>
#include <cppcms/url_dispatcher.h>
#include <cppcms/url_mapper.h>
#include <cppcms/applications_pool.h>
#include <cppcms/rpc_json.h>
#include <booster/aio/deadline_timer.h>
#include "db.h"
#include "db_key.h"

namespace peaks {
namespace pks{

/**
 *  main method to launch the server part
 *  @param vm map of configuration options
 */
void serve();


class json_service: public cppcms::rpc::json_rpc_server{
public:
    json_service(cppcms::service &srv);
    void get_stats(std::string what);
private:
    // long poll requests
    typedef std::set<booster::shared_ptr<cppcms::rpc::json_call> > waiters_type;
    waiters_type waiters_;

    // timer for resetting idle requests
    booster::aio::deadline_timer timer_;
    time_t last_wake_;
    void on_timer(booster::system::error_code const &e);
    void broadcast(std::string what);
    void remove_context(booster::shared_ptr<cppcms::rpc::json_call> call);
};


class Pks : public cppcms::application {
public:
    Pks(cppcms::service &srv);
    ~Pks() {
    }

    /**
     * method assigned to reply to the lookup query
     */
    void lookup();
    /**
     * method displaying the homepage
     */
    void homepage();
    /**
     * method assigned to reply to the hashquery
     */
    void hashquery();
    /**
     * method assigned to collect key from the client
     */
    void add();
    /**
     * method assigned to collect and display stats on the current instance
     */
    void stats();

private:
    std::shared_ptr<CGI_DBManager> dbm;
    void get(const std::string& id);
    void index(const std::string& id);
    std::string genEntry(DB_Key *keyInfo);

    void post(const std::string &temp);

    void vindex(const std::string &id);

    std::string getSignList(const std::forward_list<signature> &signatures);
    std::string getVulnList(const std::forward_list<std::string> &vulnerabilities);

    std::string fp_format(const std::string &fp);
};

}
}

#endif // PEAKS_PKS_H_
