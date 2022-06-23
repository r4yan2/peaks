#include "pks.h"
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <cstdio>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cppcms/util.h>
#include "content.h"
#include "encoder.h"
#include <PGP.h>
#include <Key.h>
#include <Packets/Packets.h>
#include <Packets/Packet.h>
#include "boost/lexical_cast.hpp"
#include <Packets/Key.h>
#include <common/errors.h>
#include <common/PacketReader.h>
#include <common/config.h>
#include <common/utils.h>
#include <regex>
#include <boost/bind.hpp>


using namespace std;
using namespace OpenPGP;

namespace peaks {
namespace pks{

const string ENTRY = "</pre><hr /><pre> \n"
"pub  %s/<a href=\"/pks/lookup?op=get&amp;search=0x%s\">%s</a> %s "
"<a href=\"/pks/lookup?op=vindex&amp;search=0x%s\">%s</a>";

// Compile time string hashing
constexpr unsigned int str2int(const char* str, int h = 0) {
    return !str[h] ? 5381 : (str2int(str, h+1)*33) ^ str[h];
}

Pks::Pks(cppcms::service &srv): cppcms::application(srv)
{

    dbm = std::make_shared<CGI_DBManager>();

    if (CONTEXT.get<int>("cgi_serve_stats") == 1){
        attach( new json_service(srv),
                "numbers", "/numbers{1}", // mapping  
                "/numbers(/(.*))?", 1);   // dispatching  
    }

    dispatcher().assign("/lookup", &Pks::lookup, this);
    mapper().assign("lookup", "/lookup");

    dispatcher().assign("/hashquery", &Pks::hashquery, this);
    mapper().assign("hashquery", "/hashquery");

    dispatcher().assign("/add", &Pks::add, this);
    mapper().assign("add", "/add");

    dispatcher().assign("/remove", &Pks::remove, this);
    mapper().assign("remove", "/remove");

    dispatcher().assign("/stats", &Pks::stats, this);
    mapper().assign("stats", "/stats");

    dispatcher().assign("", &Pks::homepage, this);
    mapper().assign("");

    mapper().root("/pks");
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

void Pks::remove(){
    if (request().request_method()=="POST"){
        syslog(LOG_DEBUG, "REMOVE");
        const string verification = request().post("_1");
        const string keyid = request().post("_2");
        remove(keyid, verification);
    }
}

void Pks::homepage() {
    content::homepage c;
    if(request().request_method()=="POST") {
        c.submit.load(context());
        c.remove.load(context());
        if(c.submit.validate()) {
            syslog(LOG_DEBUG, "SUBMIT");
            string temp = c.submit.keytext.value();
            temp.erase(std::remove(temp.begin(), temp.end(), '\r'), temp.end());
            post(temp);
        } else if(c.submit.reset.value()) {
            syslog(LOG_DEBUG, "RESET");
        }
        c.submit.clear();
        c.remove.clear();
    }
    content::homepage home;
    render("homepage", home);
}

void Pks::remove(const string& value, const string& test){
    //syslog(LOG_DEBUG, "REMOVE %s", c.remove.search.value().c_str());
    // [TODO] Implement key remove (kek)
    // [TODO] Fix that when remove is pressed, reset is triggered
    auto cert = dbm->longIDQuery(value);
    auto sig = test;
    Key::Ptr key;
    key = std::make_shared<Key>();
    key->read_raw(cert);
    key->set_type(PGP::PUBLIC_KEY_BLOCK);
    const OpenPGP::CleartextSignature signature(sig);
    const int verified = OpenPGP::Verify::cleartext_signature(*key, signature);
    if (verified && signature.get_message() == "GDPR request"){
        dbm->remove_key_from_db(hexToUll(value));
        response().status(cppcms::http::response::ok);
        response().out() << "Key deleted succesfully";
    }
}

void Pks::post(const string& arm){
    try {
        pr::readPublicKeyPacket(arm, dbm);
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
    std::string bin_key;
    int exit_code = dbm->searchKey(id, bin_key);

    if(exit_code == SUCCESS) {
        // Encode ASCII-armor key
        string pubkey;
        text_encoder::radix64 r64;

        r64.add_headers("Version: peaks 1.0");
        r64.add_headers("Comment: Hostname: localhost");

        if(!r64.encode(bin_key, pubkey)) {
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
    content::stats stats;
    syslog(LOG_INFO, "Serving stats");
    if (CONTEXT.get<int>("cgi_serve_stats") == 1){
      response().set_redirect_header("/html/stats.html");
    } else {
      stats.settings = getSettingsStats();
      stats.membership = getMembershipStats();
      render("stats", stats);
    }
}


std::string Pks::getMembershipStats(){
    std::string res = "";
    for (auto &it: CONTEXT.get<membership_t>("membership"))
      res += Utils::stringFormat("<tr>"
                                 "<td>%s</td>"
                                 "<td>%s</td>"
                                 "<td>%d</td>"
                                 "</tr>", Utils::htmlEscape(std::get<0>(it)).c_str(), Utils::htmlEscape(std::get<1>(it)).c_str(), std::get<2>(it));
    return res;
}

std::string Pks::getSettingsStats(){
    std::vector<std::string> allowed_settings = {
        "name",
        "version",
        "filters"
    };
    std::vector<std::string> allowed_settings_int = {
        "http_port",
        "recon_port"
    };

    std::string res = "";
    for (auto &it: allowed_settings)
      res += Utils::stringFormat("<tr><td>%s</td><td>%s</td></tr>", 
              Utils::htmlEscape(it).c_str(), Utils::htmlEscape(CONTEXT.get<std::string>(it, "")).c_str()
            );
    for (auto &it: allowed_settings_int)
      res += Utils::stringFormat("<tr><td>%s</td><td>%d</td></tr>", 
              Utils::htmlEscape(it).c_str(), CONTEXT.get<int>(it, 0)
            );
    return res;
}


json_service::json_service(cppcms::service &srv):
    cppcms::rpc::json_rpc_server(srv)
{
    bind("get_stats",cppcms::rpc::json_method(&json_service::get_stats,this), method_role);
}

void json_service::on_timer(booster::system::error_code const &e){
    if(e) return; // cancelation

    // check idle connections for more then 10 seconds
    if(time(0) - last_wake_ > 10) {
        broadcast("");
    }

    // restart timer
    timer_.expires_from_now(booster::ptime::seconds(5));
    timer_.async_wait(boost::bind(&json_service::on_timer, booster::intrusive_ptr<json_service>(this),_1));
}

void json_service::broadcast(std::string what)
{
    // update timeout
    last_wake_ = time(0);
    // Prepare response
    cppcms::json::value response = what;
    // Send it to everybody
    for(waiters_type::iterator waiter=waiters_.begin();waiter!=waiters_.end();++waiter) {
        booster::shared_ptr<cppcms::rpc::json_call> call = *waiter;
        call->return_result(response);
    }
    waiters_.clear();
}

cppcms::json::value parse_stats(const std::string &res){
    cppcms::json::value stats;
    if (res != ""){
        int i = 0;
        const char *start = res.data();
        if (!stats.load(start, res.end().base(), false, &i))
           std::cerr << "Error parsing string " << res << "\nat line " << i << std::endl;
    }
    return stats;
}

cppcms::json::value ptree_stats(){
    cppcms::json::value full_stats;
    syslog(LOG_INFO, "Generating ptree stats");
    std::shared_ptr<CGI_DBManager> dbm = std::make_shared<CGI_DBManager>();
    int tree_heigth = 0;
    int arity = 4;
    std::vector<DBStruct::node> nodes = dbm->get_pnodes();
    std::map<size_t, std::vector<std::string>> node_on_lv;
    std::vector<int> elements_number;
    std::map<std::string, std::vector<size_t>> prefix_map = {
        {"00", {}}, 
        {"01", {}}, 
        {"10", {}}, 
        {"11", {}}
    };
    // max 50 elements per node, buckets of 10
    std::vector<int> num_elements_buckets(5, 0);
    int i = 0;
    for (const auto& node: nodes){
        size_t keysize = node.key_size;
        node_on_lv[keysize/2].push_back(node.key);
        if (node.leaf){
            elements_number.push_back(node.num_elements);
            if (node.num_elements <= 10)
                num_elements_buckets[0] += 1;
            else if (node.num_elements <= 20)
                num_elements_buckets[1] += 1;
            else if (node.num_elements <= 30)
                num_elements_buckets[2] += 1;
            else if (node.num_elements <= 40)
                num_elements_buckets[3] += 1;
            else 
                num_elements_buckets[4] += 1;
            for (int j=0; j < num_elements_buckets.size(); j++)
                full_stats["ptree"]["num_elements_ptree_stats"][j] = num_elements_buckets[j];
            i++;
        }
        if (keysize > 0){
            auto bitstring = recon::Bitset(node.key);
            bitstring.resize(node.key_size);
            auto keystring = recon::Bitset::to_string(bitstring);
            prefix_map[keystring.substr(0,2)].push_back(keysize/2);
        }
        if (tree_heigth < keysize/2)
            tree_heigth = keysize/2;
    }

    tree_heigth++;

    std::vector<size_t> heigths;
    for (const auto& it: prefix_map){
        if (it.second.begin() != it.second.end())
            heigths.push_back(*max_element(it.second.begin(), it.second.end()));
    }
    
    int min_heigth_subtree=0;
    int max_heigth_subtree=0;

    std::vector<size_t>::iterator
        min_heigth_subtree_it,
        max_heigth_subtree_it;
    if (heigths.size() > 0){
        std::tie(min_heigth_subtree_it, max_heigth_subtree_it) = minmax_element(heigths.begin(), heigths.end());
        if (min_heigth_subtree_it != heigths.begin() or max_heigth_subtree_it != heigths.begin()){
            min_heigth_subtree = *min_heigth_subtree_it;
            max_heigth_subtree = *max_heigth_subtree_it;
        }
    }
        
    int max_num_element = 0;
    int min_num_element = 0;
    float mean_num_element = 0.0;
    float variance_num_element = 0.0;
    
    if (elements_number.begin() != elements_number.end()){
        std::vector<int>::iterator min_num_element_it = min_element(elements_number.begin(), elements_number.end());
        std::vector<int>::iterator max_num_element_it = max_element(elements_number.begin(), elements_number.end());
        if (min_num_element_it != elements_number.begin() and max_num_element_it != elements_number.begin()){
            min_num_element = *min_num_element_it;
            max_num_element = *max_num_element_it;
        }    
        //mean
        for(const int& e: elements_number) 
            mean_num_element += e;
        mean_num_element /= elements_number.size();

        //variance
        for(auto &e: elements_number) 
            variance_num_element += pow(e - mean_num_element, 2);
        variance_num_element /= elements_number.size();
    }

    full_stats["ptree"]["node_level_ptree_stats"][0] = 1;
    for (int lv = 1; lv < tree_heigth; lv++){
        full_stats["ptree"]["node_level_ptree_stats"][lv] = node_on_lv[lv].size();
    }
    full_stats["ptree"]["generic"]["Arity"] = to_string(arity);
    full_stats["ptree"]["generic"]["Total Nodes"] = to_string(nodes.size());
    full_stats["ptree"]["generic"]["Total Leaf nodes"] = to_string(elements_number.size());
    full_stats["ptree"]["generic"]["Tree Heigth"] = to_string(tree_heigth);
    full_stats["ptree"]["generic"]["Largest Leaf Node"] = to_string(max_num_element);
    full_stats["ptree"]["generic"]["Smaller Leaf Node"] = to_string(min_num_element);
    full_stats["ptree"]["generic"]["Average Leaf Node"] = to_string(mean_num_element);
    full_stats["ptree"]["generic"]["Variance in Leaf Node size"] = to_string(variance_num_element);
    full_stats["ptree"]["generic"]["Shortest tree branch"] = to_string(min_heigth_subtree);
    full_stats["ptree"]["generic"]["Longest tree branch"] = to_string(max_heigth_subtree);
    full_stats["ptree"]["generic"]["Is tree balanced?"] = (max_heigth_subtree-min_heigth_subtree <= 1)?"True":"False";

    return full_stats;
}

cppcms::json::value certificate_stats(){
    cppcms::json::value full_stats;
    syslog(LOG_INFO, "Generating ptree stats");
    std::shared_ptr<CGI_DBManager> dbm = std::make_shared<CGI_DBManager>();
    // 4 bins
    // - < 10kb
    // - 10kb -> 100kb
    // - 100kb -> 1Mb
    // - > 1Mb
    int KB = 1024;
    int MB = KB * 1024;

    std::vector<int> size_limits;
    for (int i=1; i< 10; i++){
        size_limits.push_back(i*KB);
    }
    for (int i=1; i< 10; i++){
        size_limits.push_back(10*i*KB);
    }
    for (int i=1; i< 10; i++){
        size_limits.push_back(100*i*KB);
    }
    size_limits.push_back(MB);

    time_t t = time(NULL);
    tm* timePtr = localtime(&t);
    int allowed_max_year = 1900 + timePtr->tm_year;
    int allowed_min_year = 1995;
    std::vector<int> year_limits;
    for (int i=allowed_min_year; i<=allowed_max_year; i++){
        year_limits.push_back(i);
    }
    std::map<int, int> years_counter;

    int maxsize = 0;
    int minsize = 10000000;
    int unpacked = 0;
    std::shared_ptr<DBResult> certificates_data_ptr = dbm->get_certificates_analysis_iterator();
    std::vector<int> bins(size_limits.size()+1, 0);
    int certificates = 0;
    for (; certificates < certificates_data_ptr->size(); certificates++){
        int length, year;
        bool has_ua;
        int is_unpacked;
        std::tie(length, has_ua, year, is_unpacked) = dbm->get_certificate_data_from_iterator(certificates_data_ptr);
        bool found = false;
        int i = 0;
        maxsize = std::max(maxsize, length);
        minsize = std::min(minsize, length);
        if (is_unpacked != 0)
            unpacked += 1;
        for (i=0; i<size_limits.size(); i++){
            if (length < size_limits[i]){
                bins[i] += 1;
                found = true;
                break;
            }
        }
        if (!found)
            bins[i] += 1;
        if (year >= allowed_min_year && year <= allowed_max_year)
            years_counter[year] = get(years_counter, year, 0) + 1;
    }
    int i = 0;
    for (i=0; i<bins.size() + 1; i++)
        full_stats["certificates"]["size"]["data"][i] = bins[i];
    full_stats["certificates"]["size"]["ticks"][0] = 0;
    for (int i = 0; i<size_limits.size(); i++){
        full_stats["certificates"]["size"]["ticks"][i+1] = std::to_string(size_limits[i]/KB);
    }
    full_stats["certificates"]["size"]["maxsize"] = std::to_string(maxsize/MB) + "MB";
    for (int y=allowed_min_year, i=0; y<=allowed_max_year; y++, i++){
        full_stats["certificates"]["year"]["tick"][i] = y;
        full_stats["certificates"]["year"]["value"][i] = years_counter[y];
    }

    full_stats["certificates"]["generic"]["Indexed %"] = Utils::float_format(unpacked * 100.0 / certificates, 1) + "%";
    full_stats["certificates"]["generic"]["Number of stored certificates"] = certificates;
    full_stats["certificates"]["generic"]["Largest certificate"] = std::to_string(maxsize/MB) + " MB";
    full_stats["certificates"]["generic"]["Smallest certificate"] = std::to_string(minsize) + " B";
    return full_stats;
}


cppcms::json::value userattribute_stats(){
    cppcms::json::value full_stats;
    std::shared_ptr<CGI_DBManager> dbm = std::make_shared<CGI_DBManager>();
    std::shared_ptr<DBResult> ua_data_iterator = dbm->get_user_attributes_data_iterator();
    int image_user_attributes = 0;
    int other_user_attributes = 0;
    // 4 bins
    // - < 10kb
    // - 10kb -> 100kb
    // - 100kb -> 1Mb
    // - > 1Mb
    int KB = 1024;
    int MB = KB * 1024;

    std::vector<int> limits;
    for (int i=1; i< 10; i++){
        limits.push_back(i*KB);
    }
    for (int i=1; i< 10; i++){
        limits.push_back(10*i*KB);
    }
    for (int i=1; i< 10; i++){
        limits.push_back(100*i*KB);
    }
    limits.push_back(MB);
    int maxsize_image = 0;
    int maxsize_noimage = 0;

    std::vector<int> image_bins(limits.size()+1, 0);
    std::vector<int> other_bins(limits.size()+1, 0);
    int userattributes = 0;
    for (; userattributes < ua_data_iterator->size(); userattributes++){
        int length;
        bool is_data_image;
        std::tie(length, is_data_image) = dbm->get_user_attribute_data_from_iterator(ua_data_iterator);
        if (is_data_image)
          image_user_attributes += 1;
        else
          other_user_attributes += 1;
        for (int i=0; i<limits.size(); i++){
            if (is_data_image)
                maxsize_image = std::max(maxsize_image, length);
            else
                maxsize_noimage = std::max(maxsize_noimage, length);
            if (length < limits[i]){
                if (is_data_image)
                    image_bins[i] += 1;
                else 
                    other_bins[i] += 1;
                break;
            }
        }
    }
    for (int i=0; i<image_bins.size(); i++)
        full_stats["userattributes"]["image"]["size"][i] = image_bins[i];
    for (int i=0; i<other_bins.size(); i++)
        full_stats["userattributes"]["other"]["size"][i] = other_bins[i];
    int i = 0;
    for (; i<limits.size(); i++){
        full_stats["userattributes"]["ticks"][i] = std::to_string(limits[i]/KB);
    }
    full_stats["userattributes"]["maxsize_image"] = std::to_string(maxsize_image/KB);
    full_stats["userattributes"]["maxsize_other"] = std::to_string(maxsize_noimage/KB);
    full_stats["userattributes"]["images"] = image_user_attributes;
    full_stats["userattributes"]["others"] = other_user_attributes;

    return full_stats;
}

cppcms::json::value pubkey_stats(){
    cppcms::json::value full_stats;

    std::map<int, std::map<int, int>>
        pubkey_year_alg_dict,
        vulnerability_rsa_year_dict,
        vulnerability_elgamal_year_dict,
        vulnerability_dsa_year_dict,
        vulnerability_ec_year_dict;
    std::map<int, std::vector<int>>
        rsa_year_size_dict,
        dsa_q_year_size_dict,
        dsa_p_year_size_dict,
        elgamal_year_size_dict;
    std::map<int, int>
        unhealthy_rsa_year,
        unhealthy_elgamal_year,
        unhealthy_dsa_year,
        unhealthy_ec_year,
        healthy_rsa_year,
        healthy_elgamal_year,
        healthy_dsa_year,
        healthy_ec_year;
    std::vector<int> rsa_limits = 
        {512, 1024, 2048, 4096};
    std::vector<int> elg_limits = 
        {1024, 2048, 3072};
    std::vector<int> dsa_qlimits = 
        {160, 224, 256};
    std::vector<int> dsa_plimits = 
        {1024, 2048, 3072};
    int security_limit_rsa = 1024;
    int security_limit_elgamal = 1024;
    int ec = 0;
    int rsa = 0;
    int dsa = 0;
    int elg = 0;
    time_t t = time(NULL);
    tm* timePtr = localtime(&t);
    int allowed_max_year = 1900 + timePtr->tm_year;
    int allowed_min_year = 1995;
    std::set<int>
        rsabits,
        dsa_qbits,
        dsa_pbits,
        dsayears,
        ecyears,
        elgamalyears,
        elgamalbits;
    std::map<int, int> ec_years_map;
    std::map<int, int> year_pubkey_counter;
    for (int y = allowed_min_year; y < allowed_max_year; y++)
        year_pubkey_counter[y] = 0;
    int analyzed_pubkeys = 0;

    std::shared_ptr<CGI_DBManager> dbm = std::make_shared<CGI_DBManager>();
    std::shared_ptr<DBResult> data_iterator = dbm->get_pubkey_data_iterator(allowed_min_year, allowed_max_year);

    int pubkey_count = 0;
    for (; pubkey_count < data_iterator -> size(); pubkey_count++){
        int algorithm, year, n, q, p, vulnerabilityCode, is_analyzed;
        std::string vulnerabilityDescription;
        std::tie(algorithm, year, n, p, q, vulnerabilityDescription, vulnerabilityCode, is_analyzed) = dbm->get_pubkey_data_from_iterator(data_iterator);
        auto it = algorithms_map.find(algorithm);
        if (it == algorithms_map.end())
            continue;
        if (pubkey_year_alg_dict.count(year) == 0){
            pubkey_year_alg_dict[year] = {};
        }
        pubkey_year_alg_dict[year][algorithm] = get(pubkey_year_alg_dict[year], algorithm, 0) + 1;
        for (int y=year; y<=allowed_max_year; y++)
            year_pubkey_counter[y] = get(year_pubkey_counter, y, 0) + 1;
        if (is_analyzed == 1)
            analyzed_pubkeys += 1;

        if (algorithm >=1 and algorithm <=3){
            //RSA
            rsabits.insert(n);
            rsa += 1;
            if (rsa_year_size_dict.count(year) == 0){
                rsa_year_size_dict[year] = 
                    std::vector<int>(rsa_limits.size()+1, 0);
                vulnerability_rsa_year_dict[year] = 
                    std::map<int, int>();
                unhealthy_rsa_year[year] = 0;
                healthy_rsa_year[year] = 0;
            }
            int i = 0;
            bool found = false;
            for (; i<rsa_limits.size(); i++){
                if (n < rsa_limits[i]){
                    rsa_year_size_dict[year][i] += 1;
                    found = true;
                    break;
                }
            }
            if (!found)
                rsa_year_size_dict[year][i] += 1;
            if (vulnerabilityCode != 0){
                unhealthy_rsa_year[year] += 1;
                if (vulnerabilityCode == 1 && n <= security_limit_rsa)
                    vulnerability_rsa_year_dict[year][vulnerabilityCode] = get(vulnerability_rsa_year_dict[year], vulnerabilityCode, 0) + 1;
                else
                    vulnerability_rsa_year_dict[year][vulnerabilityCode] = get(vulnerability_rsa_year_dict[year], vulnerabilityCode, 0) + 1;
            }
            else{
                healthy_rsa_year[year] += 1;
            }
        } else if (algorithm == 16){
            // Elgamal

            elgamalbits.insert(p);
            elgamalyears.insert(year);
            elg += 1;
            if (elgamal_year_size_dict.count(year) == 0){
                elgamal_year_size_dict[year] = 
                    std::vector<int>(elg_limits.size()+1, 0);
                unhealthy_elgamal_year[year] = 0;
                healthy_elgamal_year[year] = 0;
                vulnerability_elgamal_year_dict[year] = 
                    std::map<int, int>();
            }
            int i = 0;
            bool found = false;
            for (; i<elg_limits.size(); i++){
                if (p < elg_limits[i]){
                    elgamal_year_size_dict[year][i] += 1;
                    found = true;
                    break;
                }
            }
            if (!found)
                elgamal_year_size_dict[year][i] += 1;
            if (vulnerabilityCode != 0){
                unhealthy_elgamal_year[year] += 1;
                vulnerability_elgamal_year_dict[year][vulnerabilityCode] = get(vulnerability_elgamal_year_dict[year], vulnerabilityCode, 0) + 1;
            }
            else
                healthy_elgamal_year[year] += 1;
        } else if (algorithm == 17){
            // DSA

            dsa_qbits.insert(q);
            dsa_pbits.insert(p);
            dsayears.insert(year);
            dsa += 1;
            if (dsa_q_year_size_dict.count(year) == 0){
                dsa_q_year_size_dict[year] = 
                    std::vector<int>(dsa_qlimits.size()+1, 0);
                dsa_p_year_size_dict[year] = 
                    std::vector<int>(dsa_plimits.size()+1, 0);
                unhealthy_dsa_year[year] = 0;
                healthy_dsa_year[year] = 0;
                vulnerability_dsa_year_dict[year] = 
                    std::map<int, int>();
            }
            int i = 0;
            bool found = false;
            for (; i<dsa_qlimits.size(); i++){
                if (q < dsa_qlimits[i]){
                    dsa_q_year_size_dict[year][i] += 1;
                    found = true;
                    break;
                }
            }
            if (!found)
                dsa_q_year_size_dict[year][i] += 1;
            i = 0;
            found = false;
            for (; i<dsa_plimits.size(); i++){
                if (p < dsa_plimits[i]){
                    dsa_p_year_size_dict[year][i] += 1;
                    found = true;
                    break;
                }
            }
            if (!found)
                dsa_p_year_size_dict[year][i] += 1;
            if (vulnerabilityCode != 0){
                unhealthy_dsa_year[year] += 1;
                vulnerability_dsa_year_dict[year][vulnerabilityCode] = get(vulnerability_dsa_year_dict[year], vulnerabilityCode, 0) + 1;
            }
            else
                healthy_dsa_year[year] += 1;
        } else if (algorithm == 18 || algorithm == 19 || algorithm == 22){
            ecyears.insert(year);
            ec += 1;
            if (ec_years_map.count(year) == 0){
                ec_years_map[year] = 0;
                unhealthy_ec_year[year] = 0;
                healthy_ec_year[year] = 0;
                vulnerability_ec_year_dict[year] = 
                    std::map<int, int>();
            }
            ec_years_map[year] += 1;
            if (vulnerabilityCode != 0){
                unhealthy_ec_year[year] += 1;
                vulnerability_ec_year_dict[year][vulnerabilityCode] = get(vulnerability_ec_year_dict[year], vulnerabilityCode, 0) + 1;
            }
            else
                healthy_ec_year[year] += 1;
        }
    }
    
    for (const auto &it: algorithms_map){
        full_stats["pubkey"]["generic"]["algorithms_map"][it.first] = it.second;
        int i = 0;
        for (int y=allowed_min_year; y<=allowed_max_year; y++, i++){
            full_stats["pubkey"]["generic"][it.second][i] = pubkey_year_alg_dict[y][it.first];
        }
    }
    for (const auto &it: vulnerability_map){
        full_stats["pubkey"]["vulnerability"]["vulnerability_map"][it.second] = it.first;
        int i = 0;
        for (int y=allowed_min_year; y<=allowed_max_year; y++, i++){
            full_stats["pubkey"]["vulnerability"]["rsa"][it.second][i] = get(vulnerability_rsa_year_dict[y], it.first, 0);
            full_stats["pubkey"]["vulnerability"]["elgamal"][it.second][i] = get(vulnerability_elgamal_year_dict[y], it.first, 0);
            full_stats["pubkey"]["vulnerability"]["dsa"][it.second][i] = get(vulnerability_dsa_year_dict[y], it.first, 0);
            full_stats["pubkey"]["vulnerability"]["ec"][it.second][i] = get(vulnerability_ec_year_dict[y], it.first, 0);
        }
    }

    full_stats["pubkey"]["generic"]["rsa_count"] = rsa;
    full_stats["pubkey"]["generic"]["dsa_count"] = dsa;
    full_stats["pubkey"]["generic"]["elgamal_count"] = elg;
    full_stats["pubkey"]["generic"]["elliptic_count"] = ec;
    full_stats["pubkey"]["generic"]["total_valid"] = rsa+dsa+elg+ec;
    full_stats["pubkey"]["generic"]["total"] = pubkey_count;
    full_stats["pubkey"]["generic"]["analyzed %"] = Utils::float_format(analyzed_pubkeys * 100.0 / pubkey_count, 1) + "%";

    for (int y=allowed_min_year,i=0; y<=allowed_max_year; y++,i++){
        full_stats["pubkey"]["generic"]["years"][i] = y;
        full_stats["pubkey"]["generic"]["counter"][i] = year_pubkey_counter[y];
        full_stats["pubkey"]["rsa"]["n_sizes"][i] = rsa_year_size_dict[y];
        full_stats["pubkey"]["elgamal"]["p_sizes"][i] = elgamal_year_size_dict[y];
        full_stats["pubkey"]["dsa"]["p_sizes"][i] = dsa_p_year_size_dict[y];
        full_stats["pubkey"]["dsa"]["q_sizes"][i] = dsa_q_year_size_dict[y];
        full_stats["pubkey"]["elliptic"]["sizes"][i] = ec_years_map[y];
        full_stats["pubkey"]["vulnerability"]["healthy_rsa"][i] = healthy_rsa_year[y];
        full_stats["pubkey"]["vulnerability"]["unhealthy_rsa"][i] = unhealthy_rsa_year[y];
        full_stats["pubkey"]["vulnerability"]["healthy_elgamal"][i] = healthy_elgamal_year[y];
        full_stats["pubkey"]["vulnerability"]["unhealthy_elgamal"][i] = unhealthy_elgamal_year[y];
        full_stats["pubkey"]["vulnerability"]["healthy_dsa"][i] = healthy_dsa_year[y];
        full_stats["pubkey"]["vulnerability"]["unhealthy_dsa"][i] = unhealthy_dsa_year[y];
        full_stats["pubkey"]["vulnerability"]["healthy_ec"][i] = healthy_ec_year[y];
        full_stats["pubkey"]["vulnerability"]["unhealthy_ec"][i] = unhealthy_ec_year[y];
    }

    return full_stats;
}

cppcms::json::value signature_stats(){
    std::shared_ptr<CGI_DBManager> dbm = std::make_shared<CGI_DBManager>();
    cppcms::json::value full_stats;

    std::map<int, int>
        self_sig_expired,
        self_sig_revocation,
        sig_expired,
        sig_revocation,
        self_sig_valid,
        sig_valid,
        self_sig,
        sig;
    int
        self_sig_expired_count = 0,
        self_sig_revocation_count = 0,
        sig_expired_count = 0,
        sig_revocation_count = 0,
        self_sig_valid_count = 0,
        sig_valid_count = 0,
        self_sig_count = 0,
        sig_count = 0;

    time_t t = time(NULL);
    tm* timePtr = localtime(&t);
    int allowed_max_year = 1900 + timePtr->tm_year;
    int allowed_min_year = 1995;

    std::map<int, std::map<int,int>> signature_year_alg_dict;

    std::shared_ptr<DBResult> data_iterator = dbm->get_signature_data_iterator();
    int signature_count = 0;

    for (; signature_count < data_iterator->size(); signature_count++){
        int isRevocation, isExpired, pubAlgorithm, year, issuingKeyId, signedKeyId;
        std::tie(isRevocation, isExpired, pubAlgorithm, year, issuingKeyId, signedKeyId) = dbm->get_signature_data_from_iterator(data_iterator);
        if (issuingKeyId == signedKeyId){
            self_sig[year] = get(self_sig, year, 0) + 1;
            if (isExpired)
                self_sig_expired[year] = get(self_sig_expired, year, 0) + 1;
            else
                self_sig_valid[year] = get(self_sig_valid, year, 0) + 1;
            if (isRevocation)
                self_sig_revocation[year] = get(self_sig_revocation, year, 0) + 1;
        } else {
            sig[year] = get(sig, year, 0) + 1;
            if (isExpired)
                sig_expired[year] = get(sig_expired, year, 0) + 1;
            else
                sig_valid[year] = get(sig_valid, year, 0) + 1;
            if (isRevocation)
                sig_revocation[year] = get(sig_revocation, year, 0) + 1;
        }
        if (signature_year_alg_dict.count(year) == 0)
            signature_year_alg_dict[year] = {{}};
        signature_year_alg_dict[year][pubAlgorithm] = get(signature_year_alg_dict[year], pubAlgorithm, 0) + 1;
    }
    auto f = [=](std::map<int, int> m){int sum = 0; for (const auto& it: m) sum+=it.second;return sum;};
    int i = 0;
    for (int y=allowed_min_year,i=0; y<=allowed_max_year; y++,i++)
        full_stats["signature"]["static"]["years"][i] = y;

    for (const auto &it: algorithms_map){
        full_stats["signature"]["static"]["algorithms_map"][it.first] = it.second;
        for (int y=allowed_min_year, i=0; y<=allowed_max_year; y++, i++){
            full_stats["signature"]["year"][it.second][i] = signature_year_alg_dict[y][it.first];
        }
    }
    for (int y=allowed_min_year, i=0; y<=allowed_max_year; y++, i++){
        full_stats["signature"]["year"]["self signatures"][i] = self_sig[y];
        full_stats["signature"]["year"]["self signatures valid"][i] = self_sig_valid[y];
        full_stats["signature"]["year"]["self signatures expired"][i] = self_sig_expired[y];
        full_stats["signature"]["year"]["self signatures revocation"][i] = self_sig_revocation[y];
        full_stats["signature"]["year"]["signatures"][i] = sig[y];
        full_stats["signature"]["year"]["signatures valid"][i] = sig_valid[y];
        full_stats["signature"]["year"]["signatures expired"][i] = sig_expired[y];
        full_stats["signature"]["year"]["signatures revocation"][i] = sig_revocation[y];
    }

    full_stats["signature"]["generic"]["total"] = signature_count;
    full_stats["signature"]["generic"]["signatures"] = f(sig);
    full_stats["signature"]["generic"]["signatures valid"] = f(sig_valid);
    full_stats["signature"]["generic"]["signatures expired"] = f(sig_expired);
    full_stats["signature"]["generic"]["signatures revocation"] = f(sig_revocation);
    full_stats["signature"]["generic"]["self signatures"] = f(self_sig);
    full_stats["signature"]["generic"]["self signatures valid"] = f(self_sig_valid);
    full_stats["signature"]["generic"]["self signatures expired"] = f(self_sig_expired);
    full_stats["signature"]["generic"]["self signatures revocations"] = f(self_sig_revocation);

    return full_stats;
}

cppcms::json::value userid_stats(){
    std::shared_ptr<CGI_DBManager> dbm = std::make_shared<CGI_DBManager>();
    cppcms::json::value full_stats;

    int
        PPA_mail = 0,
        PPA_nomail = 0,
        PPA_keyid = 0,
        no_mail = 0,
        no_name = 0;
    size_t max_length = 0;
    std::vector<std::string>
        urls,
        names,
        hosts,
        magnets;
    std::vector<int> size_limits;
    for (int i=10; i < 100; i+=10){
        size_limits.push_back(i);
    }
    for (int i=100; i <= 1000; i+=100){
        size_limits.push_back(i);
    }
  

    std::map<std::string, std::set<std::string>> domain_dict;
    std::vector<int> username_lengths;
    regex link_pattern("(https?|ftp)://([^/\r\n]+/[^\r\n]*?)");
    regex mail_pattern("([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)");
    
    std::shared_ptr<DBResult> data_iterator = dbm->get_userid_data_iterator();
    std::vector<int> bins(size_limits.size()+1, 0);
    int userid_count = 0;

    for (; userid_count < data_iterator->size(); userid_count++){
        int ownerkeyid;
        std::string name;
        std::tie(ownerkeyid, name) = dbm->get_userid_data_from_iterator(data_iterator);

        size_t size = name.size();
        max_length = std::max(size, max_length);
        if (size == 0){
            no_name += 1;
            continue;
        }
        bool found = false;
        int i = 0;
        for (i=0; i<size_limits.size(); i++){
            if (size < size_limits[i]){
                bins[i] += 1;
                found = true;
                break;
            }
        }
        if (!found)
            bins[i] += 1;
        username_lengths.push_back(size);

        auto words_begin = sregex_iterator(name.begin(), name.end(), mail_pattern);
        auto words_end = sregex_iterator();
    
        for (sregex_iterator i = words_begin; i != words_end; i++) {
            string host = (*i)[1].str();
            string domain = (*i)[2].str();
            if (domain_dict.count(domain) == 0)
                domain_dict[domain] = {};
            domain_dict[domain].insert(host);
            if (is_substring(name, "PPA") || is_substring(name, "Launchpad"))
                PPA_mail += 1;
            
        }

        if (words_begin == words_end){
            if (is_substring(name, "PPA") || is_substring(name, "Launchpad"))
                PPA_nomail += 1;
            else
                no_mail += 1;
        }

        words_begin = sregex_iterator(name.begin(), name.end(), mail_pattern);
        words_end = sregex_iterator();
        for (sregex_iterator i = words_begin; i != words_end; i++) {
            string proto = (*i)[1].str();
            string url = (*i)[2].str();
            urls.push_back(name);
        }

        if (is_substring(name, "magnet:")){
            magnets.push_back(name);
        }
    
    }

    auto f = [=](std::map<std::string, std::set<std::string>> m){int sum = 0; for (const auto& it: m) sum+=it.second.size();return sum;};
    full_stats["userid"]["generic"]["UserIDs in database"] = userid_count;
    full_stats["userid"]["generic"]["PPA found"] = PPA_mail + PPA_nomail;
    full_stats["userid"]["generic"]["PPA with mail"] = PPA_mail;
    full_stats["userid"]["generic"]["PPA without mail"] = PPA_nomail;
    full_stats["userid"]["generic"]["Userid with no mail"] = no_mail;
    full_stats["userid"]["generic"]["Mail Domains found"] = domain_dict.size();
    full_stats["userid"]["generic"]["Unique mail adddresses found"] = f(domain_dict);
    full_stats["userid"]["generic"]["url found in username"] = urls.size();
    full_stats["userid"]["generic"]["skipped username"] = no_name;
    full_stats["userid"]["generic"]["magnets found"] = magnets.size();

    std::vector<std::pair<std::string, size_t>> pairs;
    for (const auto& it: domain_dict)
        pairs.push_back(make_pair(it.first, it.second.size()));
    
    sort(pairs.begin(), pairs.end(), [=](std::pair<std::string, size_t>& a, std::pair<std::string, size_t>& b)
    {
        return a.second > b.second;
    }
    );
    int limit = 20;
    int i = 0;
    for (const auto &it: pairs){
        if (i > limit) break;
        full_stats["userid"]["domain"]["label"][i] = it.first;
        full_stats["userid"]["domain"]["value"][i] = it.second;
        i++;
    }
    for (int i=0; i<bins.size(); i++)
        full_stats["userid"]["size"]["value"][i] = bins[i];
    i = 0;
    for (; i<size_limits.size(); i++)
        full_stats["userid"]["size"]["label"][i] = size_limits[i];
    if (max_length > size_limits.back())
        full_stats["userid"]["size"]["label"][i] = max_length;

    return full_stats;
}

void json_service::remove_context(booster::shared_ptr<cppcms::rpc::json_call> call)
{
    waiters_.erase(call);
}

void json_service::get_stats(std::string what){
    std::map<std::string, std::function<cppcms::json::value()>> function_map = {
        {"ptree", ptree_stats},
        {"certificates", certificate_stats},
        {"userattributes", userattribute_stats},
        {"pubkey", pubkey_stats},
        {"signature", signature_stats},
        {"userid", userid_stats}
    };
    std::shared_ptr<CGI_DBManager> dbm = std::make_shared<CGI_DBManager>();
    std::string res = "";
    bool expired = ( dbm->get_from_cache(what, res) > CONTEXT.get<int>("expire_interval") * 24 * 60 * 60 );
    if (res == ""){
        cppcms::json::value all_stats = "";
        auto f = function_map.find(what);
        if (f == function_map.end()){
            return_result(all_stats); // ???
            return;
        }
        std::string out;
        if (CONTEXT.get<bool>("recompute"+what)){
            //recompute already in progress
            return_result(all_stats);
            return;
        }
        // computing will take a while. client will need to request again
        return_result(all_stats);
        CONTEXT.set("recompute"+what, true);
        all_stats = f->second();
        std::string value = all_stats[what].save();
        dbm->store_in_cache(what, value);
        CONTEXT.set("recompute"+what, false);
    } else {
        // serve last results even if expired
        cppcms::json::value stats = parse_stats(res);
        return_result(stats);
        if (expired){
            // recalculate expired data
            auto f = function_map.find(what);
            if (f != function_map.end()){
                if (CONTEXT.get<bool>("recompute"+what)){
                    //recompute already in progress
                    return;
                }
                CONTEXT.set("recompute"+what, true);
                auto new_stats = f->second();
                std::string value = new_stats[what].save();
                dbm->store_in_cache(what, value);
                CONTEXT.set("recompute"+what, false);
            }
        }
    }
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
    full_key key;
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

void serve(){
    cppcms::json::value cfg;
    cfg["service"]["api"] = "http";
    cfg["service"]["port"] = CONTEXT.get<int>("http_port");
    cfg["service"]["ip"] = CONTEXT.get<std::string>("pks_bind_ip");
    cfg["http"]["script_names"][0] = "/pks";
    cfg["file_server"]["enable"] = true;
    cfg["file_server"]["document_root"] = CONTEXT.get<std::string>("web_assets_folder");
    cfg["file_server"]["listing"] = false;
    //cfg["file_server"]["alias"][0]["url"] = "/css";
    //cfg["file_server"]["alias"][0]["path"] = "static/css";
    //cfg["file_server"]["alias"][1]["url"] = "/js";
    //cfg["file_server"]["alias"][1]["path"] = "static/js";

    try {
        cppcms::service srv(cfg);
        srv.applications_pool().mount(cppcms::applications_factory<Pks>());
        srv.run();
    }
    catch(std::exception const &e) {
        std::cerr << e.what() << std::endl;
        syslog(LOG_CRIT, "Error during starting up: %s", e.what());
    }

    std::cout << "Exiting..." << std::endl;
    closelog();
}

}
}
