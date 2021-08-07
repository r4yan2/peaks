#ifndef PEAKS_PKS_H_
#define PEAKS_PKS_H_

#include <cppcms/service.h>
#include <cppcms/url_dispatcher.h>
#include <cppcms/url_mapper.h>
#include <cppcms/applications_pool.h>
#include "db.h"
#include "db_key.h"
#include <boost/program_options.hpp>

namespace po = boost::program_options;
namespace peaks {
namespace pks{

/**
 *  main method to launch the server part
 *  @param vm map of configuration options
 */
void serve(po::variables_map &vm);

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
