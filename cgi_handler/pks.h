#ifndef PEAKS_PKS_H_
#define PEAKS_PKS_H_

#include <cppcms/application.h>
#include <cppcms/service.h>
#include <cppcms/http_response.h>
#include <cppcms/url_dispatcher.h>
#include <cppcms/url_mapper.h>
#include <cppcms/applications_pool.h>
#include <cppcms/http_request.h>
#include "db.h"
#include "db_key.h"
#include <boost/program_options.hpp>

namespace po = boost::program_options;

void serve(po::variables_map &vm, po::parsed_options &parsed);
namespace peaks {

class Pks : public cppcms::application {
public:
    Pks(cppcms::service &srv, const Cgi_DBConfig &db_config) : cppcms::application(srv) {
        dbm = new DBManager(db_config);

        dispatcher().assign("/lookup", &Pks::lookup, this);
        mapper().assign("lookup", "/lookup");

        dispatcher().assign("/hashquery", &Pks::hashquery, this);
        mapper().assign("hashquery", "/hashquery");

        dispatcher().assign("", &Pks::homepage, this);
        mapper().assign("");

        mapper().root("/pks");
    }
    ~Pks() {
        delete dbm;
    }

    void lookup();
    void homepage();
    void hashquery();

private:
    DBManager* dbm;
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
