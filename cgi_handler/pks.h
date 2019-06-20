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

/**
 *  main method to launch the server part
 *  @param vm map of configuration options
 *  @param parsed original command line parsed
 */
void serve(po::variables_map &vm, po::parsed_options &parsed);
namespace peaks {

class Pks : public cppcms::application {
public:
    Pks(cppcms::service &srv, const DBSettings & db_config) : cppcms::application(srv) {
        dbm = std::make_unique<CGI_DBManager>(db_config);

        dispatcher().assign("/lookup", &Pks::lookup, this);
        mapper().assign("lookup", "/lookup");

        dispatcher().assign("/hashquery", &Pks::hashquery, this);
        mapper().assign("hashquery", "/hashquery");

        dispatcher().assign("/add", &Pks::add, this);
        mapper().assign("add", "/add");

        dispatcher().assign("/stats", &Pks::stats, this);
        mapper().assign("stats", "/stats");

        dispatcher().assign("", &Pks::homepage, this);
        mapper().assign("");

        mapper().root("/pks");
    }
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
    std::unique_ptr<CGI_DBManager> dbm;
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

#endif // PEAKS_PKS_H_
