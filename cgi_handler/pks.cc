#include "pks.h"
#include <iostream>
#include <string>
#include <cstdio>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cppcms/util.h>
#include "utils.h"
#include "content.h"
#include "encoder/encoder.h"
#include <PGP.h>
#include <Key.h>
#include <Packets/packets.h>
#include <Packets/Packet.h>
#include "boost/lexical_cast.hpp"
#include <Packets/Key.h>
#include <common/errors.h>
#include "PacketReader.h"


using namespace peaks;
using namespace std;
using namespace OpenPGP;

const string ENTRY = "</pre><hr /><pre> \n"
"pub  %s/<a href=\"/pks/lookup?op=get&amp;search=0x%s\">%s</a> %s "
"<a href=\"/pks/lookup?op=vindex&amp;search=0x%s\">%s</a>";

// Compile time string hashing
constexpr unsigned int str2int(const char* str, int h = 0) {
    return !str[h] ? 5381 : (str2int(str, h+1)*33) ^ str[h];
}

void Pks::lookup() {
    // Retrieve and parse querystring
    string query_string = request().query_string();
    map<string, string> query_map = Utils::parse(query_string);
    const char* operation = query_map["op"].c_str();
    const string search_string = cppcms::util::urldecode(query_map["search"]);
    switch(str2int(operation)) {
        case str2int("get"):
            get(search_string);
            break;
        case str2int("index"):
            index(search_string);
            break;
        case str2int("vindex"):
            vindex(search_string);
            break;
        default:
            // Unknown operation
            response().status(cppcms::http::response::not_implemented);
            response().out() << "Not implemented";
    }
}

void Pks::hashquery(){
    if (request().request_method()=="POST"){
        std::pair<void *, size_t> body = request().raw_post_data();
        string body_str = std::string((const char *)body.first, request().content_length());
        vector<string> hashes;
        const unsigned long list_length = toint(hexlify(body_str.substr(0, 4)), 16);
        for (unsigned int i = 0, j = 4; i < list_length; i++){
            unsigned long hash_length = toint(hexlify(body_str.substr(j, 4)), 16);
            hashes.push_back(hexlify(body_str.substr(j + 4, hash_length)));
            j += 4 + hash_length;
        }
        vector<string> result;
        for (const auto &hash: hashes){
            string tmp_cert = dbm->get_key_by_hash(hash);
            result.push_back(unhexlify(makehex(tmp_cert.size(), 8)) + tmp_cert);
        }

        string certificates = unhexlify(makehex(result.size(), 8));
        for (const auto &c: result){
            certificates += c;
        }
        response().status(cppcms::http::response::ok);
        response().content_type("pgp/keys");
        response().content_length(certificates.length());
        response().out() << certificates;

    }else{
        response().status(cppcms::http::response::not_implemented);
    }
}


void Pks::add(){
    if (request().request_method()=="POST"){
        syslog(LOG_DEBUG, "SUBMIT");
        const string keytext = request().post("keytext");
        post(keytext);

    }else{
        response().status(cppcms::http::response::not_implemented);
    }
}

void Pks::homepage() {
    content::homepage c;
    if(request().request_method()=="POST") {
        c.submit.load(context());
        c.remove.load(context());
        if(c.submit.submit.value()) {
            syslog(LOG_DEBUG, "SUBMIT");
            string temp = c.submit.keytext.value();
            temp.erase(std::remove(temp.begin(), temp.end(), '\r'), temp.end());
            post(temp);
        } else if(c.submit.reset.value()) {
            syslog(LOG_DEBUG, "RESET");
        } else if(c.remove.submit.value()) {
            syslog(LOG_DEBUG, "REMOVE %s", c.remove.search.value().c_str());
            // [TODO] Implement key remove (kek)
            // [TODO] Fix that when remove is pressed, reset is triggered
        }
        c.submit.clear();
        c.remove.clear();
    }
    content::homepage home;
    render("homepage", home);
}


void Pks::post(const string& arm){
    try {
        pr::readPublicKeyPacket(arm, dbm.get());
        response().status(cppcms::http::response::ok);
        response().out() << "Key uploaded succesfully";
    }catch (error_code &ec){
        switch (ec.value()){
            case static_cast<int>(KeyErrc::BadKey):
                response().status(cppcms::http::response::internal_server_error);
                response().out() << "Not a PGP Public Key";
            case static_cast<int>(KeyErrc::NotAPublicKey):
                response().status(cppcms::http::response::internal_server_error);
                response().out() << "ERROR: you have uploaded a PRIVATE KEY! You shold revoke it IMMEDIATELY";
            default:
                cerr << ec.message() << endl;
                response().status(cppcms::http::response::internal_server_error);
                response().out() << "Error during the upload of the key. Please contact the administrator.";
                syslog(LOG_CRIT, "GENERIC ERROR: (%s) during upload of key", ec.message().c_str());
                break;
        }
        dbm->insert_broken_key(pr::get_ascii_arm(arm), ec.message());
    }catch (runtime_error &e){
        cout << e.what() << endl;
        response().status(cppcms::http::response::internal_server_error);
        response().out() << "Error during the upload of the key. Please contact the administrator.";
        syslog(LOG_ERR, "Error (%s) during upload of key", e.what());
        dbm->insert_broken_key(pr::get_ascii_arm(arm), e.what());
    }catch (logic_error &e){
        cerr << e.what() << endl;
        response().status(cppcms::http::response::internal_server_error);
        response().out() << "Error during the upload of the key. Please contact the administrator.";
        syslog(LOG_CRIT, "LOGIC ERROR: (%s) during upload of key", e.what());
        dbm->insert_broken_key(pr::get_ascii_arm(arm), e.what());
    }catch (exception &e){
        cerr << e.what() << endl;
        response().status(cppcms::http::response::internal_server_error);
        response().out() << "Error during the upload of the key. Please contact the administrator.";
        syslog(LOG_CRIT, "GENERIC ERROR: (%s) during upload of key", e.what());
        dbm->insert_broken_key(pr::get_ascii_arm(arm), e.what());
    }
}


void Pks::get(const string& id) {
    syslog(LOG_INFO, "Looking up key with id: %s", id.c_str());
    // Query key from database
    std::shared_ptr<istream> bin_key;
    int exit_code = dbm->searchKey(id, bin_key);

    if(exit_code == SUCCESS) {
        // Encode ASCII-armor key
        string pubkey;
        text_encoder::radix64 r64;

        r64.add_headers("Version: peaks 1.0");
        r64.add_headers("Comment: Hostname: localhost");

        if(!r64.encode(*bin_key, pubkey)) {
            syslog(LOG_ERR, "Failed to encode key in radix64 with id %s!", id.c_str());
        }
        // Content initialization
        content::certificate cert;
        cert.keyID = Utils::toLower(id);
        cert.pubkey = pubkey;
        render("certificate", cert);
    }
    else if (exit_code == KEY_NOT_FOUND) {
        response().status(cppcms::http::response::not_found);
        response().out() << "No results found";
    }
    else {
        syslog(LOG_ERR, "Database error!");
    }
}

void Pks::stats(){
    std::string page;

    syslog(LOG_INFO, "Serving stats");
    int tree_heigth = 0;
    int arity = 4;
    std::vector<pnode> nodes = dbm->get_pnodes();
    std::map<size_t, std::vector<std::string>> leaf_on_lv;
    std::vector<int> elements_number;
    std::map<std::string, std::vector<size_t>> prefix_map = {
        {"00", {}}, 
        {"01", {}}, 
        {"10", {}}, 
        {"11", {}}
    };
    for (auto const& node: nodes){
        size_t keysize = node.node_key.size();
        if (node.leaf){
            leaf_on_lv[keysize/2].push_back(node.node_key);
            elements_number.push_back(node.num_elements);
        }
        if (keysize > 0){
            prefix_map[node.node_key.substr(0,2)].push_back(keysize/2);
        }
        if (tree_heigth < keysize/2)
            tree_heigth = keysize/2;
    }
    tree_heigth++;

    std::vector<size_t> heigths;
    for (auto const& it: prefix_map){
        heigths.push_back(*max_element(it.second.begin(), it.second.end()));
    }
    
    int min_heigth_subtree=0;
    int max_heigth_subtree=0;

    std::vector<size_t>::iterator
        min_heigth_subtree_it,
        max_heigth_subtree_it;
    std::tie(min_heigth_subtree_it, max_heigth_subtree_it) = minmax_element(heigths.begin(), heigths.end());
    if (min_heigth_subtree_it != heigths.begin() or max_heigth_subtree_it != heigths.begin()){
        min_heigth_subtree = *min_heigth_subtree_it;
        max_heigth_subtree = *max_heigth_subtree_it;
    }
        
    int max_num_element = 0;
    int min_num_element = 0;
    
    std::vector<int>::iterator min_num_element_it = min_element(elements_number.begin(), elements_number.end());
    std::vector<int>::iterator max_num_element_it = max_element(elements_number.begin(), elements_number.end());
    if (min_num_element_it != elements_number.begin() and max_num_element_it != elements_number.begin()){
        min_num_element = *min_num_element_it;
        max_num_element = *max_num_element_it;
    }
        
    float mean_num_element = 0;
    for(int const& e: elements_number) 
        mean_num_element += e;
    mean_num_element /= elements_number.size();

    float variance_num_element = 0;
    for(auto &e: elements_number) 
        variance_num_element += pow(e - mean_num_element, 2);
    variance_num_element /= elements_number.size();

    std::vector<size_t> nodes_per_lv;
    size_t inner_nodes = 1; //root node
    nodes_per_lv.push_back(1);
    for (int lv = tree_heigth; lv < tree_heigth; lv++){
        size_t leaf_nodes = leaf_on_lv[lv].size();
        size_t nodes_on_cur_lv = inner_nodes * arity;
        inner_nodes = nodes_on_cur_lv - leaf_nodes;
        nodes_per_lv.push_back(nodes_on_cur_lv);
    }

    page = Utils::stringFormat(
            "<h1>Stats</h1>"
                    "<h3>Ptree</h3>"
                    "<table>"
                    "<tr>"
                        "<th>Field</th>"
                        "<th>Value</th>"
                    "</tr>"
                    "<tr>"
                        "<td>%s</td>"
                        "<td>%d</td>"
                    "</tr>"
                    "<tr>"
                        "<td>%s</td>"
                        "<td>%lu</td>"
                    "</tr>"
                    "<tr>"
                        "<td>%s</td>"
                        "<td>%lu</td>"
                    "</tr>"
                    "<tr>"
                        "<td>%s</td>"
                        "<td>%d</td>"
                    "</tr>"
                    "<tr>"
                        "<td>%s</td>"
                        "<td>%d</td>"
                    "</tr>"
                    "<tr>"
                        "<td>%s</td>"
                        "<td>%f</td>"
                    "</tr>"
                    "<tr>"
                        "<td>%s</td>"
                        "<td>%f</td>"
                    "</tr>"
                    "<tr>"
                        "<td>%s</td>"
                        "<td>%d</td>"
                    "</tr>"
                    "<tr>"
                        "<td>%s</td>"
                        "<td>%d</td>"
                    "</tr>"
                    "<tr>"
                        "<td>%s</td>"
                        "<td>%s</td>"
                    "</tr>"
                    "</table>",
                "Arity", arity,
                "Total nodes number", nodes.size(),
                "Leaf nodes", elements_number.size(),
                "Largest leaf node", max_num_element,
                "Smaller leaf node", min_num_element,
                "Average leaf node", mean_num_element,
                "Variance in leaf node size", variance_num_element,
                "Shortest tree branch", min_heigth_subtree,
                "Longest tree branch", max_heigth_subtree,
                "Is tree balanced?", min_heigth_subtree==max_heigth_subtree?"True":"False"
            );
    response().out() << page;
}

void Pks::index(const string& id) {
    content::index index;
    string results = string();

    if(id.size() == 0) {
        response().status(cppcms::http::response::not_found);
        response().out() << "Empty input!";
        return;
    }

    syslog(LOG_INFO, "Serving index for id: %s", id.c_str());
    forward_list<DB_Key*> *indexList = dbm->indexQuery(id);

    // Build results page
    for (DB_Key* key : *indexList) {
        results += genEntry(key);
        delete key;
    }
    delete indexList;

    index.searchString = Utils::toLower(id);
    index.results = results;
    render("index", index);
}

void Pks::vindex(const string& id) {
    content::vindex vindex;
    string page_template; // = Utils::stringFormat("</pre><hr /><pre>");

    if(id.empty()) {
        response().status(cppcms::http::response::not_found);
        response().out() << "Empty input!";
        return;
    }

    syslog(LOG_INFO, "Serving index for id: %s", id.c_str());
    peaks::full_key key;
    try{
        key = dbm->vindexQuery(id.substr(2));
    }catch (exception &e){
        response().status(cppcms::http::response::bad_request);
        return;
    }
    if(key.Primary_Key.keyID.empty()) {
        response().status(cppcms::http::response::not_found);
        response().out() << "No results found";
        return;
    }
    string fingerprint = fp_format(key.Primary_Key.fingerprint);
    page_template += Utils::stringFormat(
            "<tr>"
                    "<td><b>pub</b></td>"
                    "<td>%s</td>"
                    "<td><a href=\"/pks/lookup?op=get&amp;search=0x%s\">%s</a></td>"
                    "<td>%s</td>"
                    "<td colspan=\"3\">__________</td>"
                    "%s",
            Utils::htmlEscape(key.Primary_Key.bits + key.Primary_Key.algoChar).c_str(),
            Utils::htmlEscape(key.Primary_Key.keyID).c_str(),
            Utils::htmlEscape(key.Primary_Key.keyID.substr(key.Primary_Key.keyID.size()-8, 8)).c_str(),
            Utils::htmlEscape(key.Primary_Key.creation_time).c_str(),
            getVulnList(key.Primary_Key.vulnerabilities).c_str());
    page_template += getSignList(key.Primary_Key.signatures);
    page_template += Utils::stringFormat("<tr>"
                                         "<td></td>"
                                         "<td colspan=\"2\">Fingerprint:</td>"
                                         "<td colspan=\"7\">%s</td>"
                                         "</tr>" , Utils::htmlEscape(fingerprint).c_str());
    for (const auto &uid: key.users){
        page_template += Utils::stringFormat("<tr style=\"height: 10px !important;\">"
                                             "    <td colspan=\"9\"></td>"
                                             "</tr>"
                                             "<tr>"
                                             "<td><b>uid</b></td>"
                                             "<td colspan=\"8\" class=\"uid\"><span>%s</span></td>"
                                             "</tr>",
                                             Utils::htmlEscape(uid.name).c_str());
        page_template += getSignList(uid.signatures);
        for (const auto &uatt: uid.user_attributes){
            page_template += Utils::stringFormat("<tr style=\"height: 10px !important;\">"
                                                 "    <td colspan=\"9\"></td>"
                                                 "<tr>"
                                                 "<td><b>uat</b></td>"
                                                 "<td colspan=\"8\">[contents omitted]</td>"
                                                 "</tr>");
            page_template += getSignList(uatt.signatures);
        }
    }
    for (const auto &subk: key.subkeys){
        page_template += Utils::stringFormat(
                "<tr style=\"height: 10px !important;\">"
                "    <td colspan=\"9\"></td>"
                "</tr>"
                "<tr>"
                "<td><b>sub</b></td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td colspan=\"4\">%s</td>"
                "%s",
                Utils::htmlEscape(subk.bits + subk.algoChar).c_str(),
                Utils::htmlEscape(subk.keyID.substr(subk.keyID.size()-8, 8)).c_str(),
                Utils::htmlEscape(subk.creation_time).c_str(),+
                getVulnList(subk.vulnerabilities).c_str());
        page_template += getSignList(subk.signatures);
    }

    vindex.searchString = Utils::toLower(id);
    vindex.key_component = page_template;
    render("vindex", vindex);
}

string Pks::fp_format(const string &fp){
    string out = "";
    for (unsigned int i = 0; i < fp.size(); i++){
        if (i == (fp.size() / 2)){
            out += "  ";
        }else if (i != 0 && i % 4 == 0){
            out += " ";
        }
        out += fp[i];
    }
    return out;
}

string Pks::getSignList(const forward_list<signature> &signatures){
    string page_template = "";
    for (const auto &sign: signatures){
        std::string tmp_template = "<tr><td>sig</td>";
        if (sign.type == "revok" || sign.type == "exp"){
            tmp_template += "<td class=\"warn\"><b>%s</b></td>";
        }else{
            tmp_template += "<td>%s</td>";
        }
        tmp_template += "<td><a href=\"/pks/lookup?op=get&amp;search=0x%s\">%s</a></td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td><a href=\"/pks/lookup?op=vindex&fingerprint=on&search=0x%s\">%s</a></td>"
                "%s";
        page_template += Utils::stringFormat(
                tmp_template,
                Utils::htmlEscape(sign.type).c_str(),
                Utils::htmlEscape(sign.issuingKeyID).c_str(),
                Utils::htmlEscape(sign.issuingKeyID.substr(sign.issuingKeyID.size()-8, 8)).c_str(),
                Utils::htmlEscape(sign.creation_time).c_str(),
                Utils::htmlEscape(sign.exp_time).c_str(),
                Utils::htmlEscape(sign.key_exp_time).c_str(),
                Utils::htmlEscape(sign.issuingKeyID).c_str(),
                Utils::htmlEscape(sign.issuingUID).c_str(),
                getVulnList(sign.vulnerabilities).c_str());
    }
    return page_template;
}

string Pks::getVulnList(const forward_list<string> &vulnerabilities){
    unsigned int count_vuln = 0;
    string ret = "<td rowspan=\"%s\"></td>";
    for (const auto &v: vulnerabilities){
        if (!count_vuln){
            ret += "<td>" + Utils::htmlEscape(v) + "</td></tr>";
        }else{
            ret += "<tr><td colspan=\"8\"></td><td>" + Utils::htmlEscape(v) + "</td></tr>";
        }
        count_vuln++;
    }
    if (count_vuln){
        return Utils::stringFormat(ret, to_string(count_vuln).c_str());
    }
    return "</tr>";
}

string Pks::genEntry(DB_Key *keyInfo) {
    if (keyInfo->algo == 0) {keyInfo->bits = 0;}
    string bitsAlgo = to_string(keyInfo->bits) + keyInfo->algo;
    string keyID = keyInfo->keyID;
    string shortID = keyID.substr(keyID.size()-8, 8);
    string date = keyInfo->date;
    string userID = keyInfo->userID;
    bitsAlgo = Utils::htmlEscape(bitsAlgo);
    keyID = Utils::htmlEscape(keyID);
    shortID = Utils::htmlEscape(shortID);
    date = Utils::htmlEscape(date);
    userID = Utils::htmlEscape(userID);
    return Utils::stringFormat(ENTRY, bitsAlgo.c_str(), keyID.c_str(),
                               shortID.c_str(), date.c_str(), keyID.c_str(),
                               userID.c_str());
}

void serve(po::variables_map &vm, po::parsed_options &parsed){
   po::options_description serve_desc("serve options");
   std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
   if (std::find(opts.begin(), opts.end(), "-c") == opts.end()){
       opts.push_back("-c");
       opts.push_back(vm["cppcms_config"].as<std::string>());
   }
   std::vector<char *> new_argv;
   std::transform(opts.begin(), opts.end(), std::back_inserter(new_argv), [](const std::string s) -> char* {
           char *pc = new char[s.size() + 1];
           std::strcpy(pc, s.c_str());
           return pc;
           }
           );

    const DBSettings cgi_settings = {
        vm["db_user"].as<std::string>(),
        vm["db_password"].as<std::string>(),
        vm["db_host"].as<std::string>(),
        vm["db_database"].as<std::string>()
    };

    int log_option;
    int log_upto;

    if (vm.count("stdout")){
        std::cout << "logging to stdout" << std::endl;
        log_option = LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID;
    }
    else{
        log_option = LOG_PID;
    }
    if (vm.count("debug")){
        std::cout << "debug output" << std::endl;
        log_upto = LOG_UPTO(LOG_DEBUG);
    }
    else{
        log_upto = LOG_UPTO(LOG_INFO); 
    }

    openlog("peaks_serve", log_option, LOG_USER);
    setlogmask(log_upto);
 
    syslog(LOG_NOTICE, "peaks server is starting up!");
    try {
        cppcms::service srv(opts.size(), &new_argv[0]);
        srv.applications_pool().mount(cppcms::applications_factory<Pks>(cgi_settings));
        srv.run();
    }
    catch(std::exception const &e) {
        std::cerr << e.what() << std::endl;
        syslog(LOG_CRIT, "Error during starting up: %s", e.what());
    }

    std::cout << "Exiting..." << std::endl;
    closelog();
}

