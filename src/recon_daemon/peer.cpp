#include "peer.h"
#include <common/utils.h>
#include <common/config.h>
#include <NTL/matrix.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ_pXFactoring.h>
#include <algorithm>
#include <cmath>
#include <curl/curl.h>
#include <common/PacketReader.h>

namespace peaks{
namespace recon{
PeerManager::PeerManager():
    cn()
{}

Connection PeerManager::choose_partner(){
    auto membership = CONTEXT.get<membership_t>("membership");
    int choice = Utils::get_random(membership.size());
    member m(std::get<1>(membership[choice]), std::get<2>(membership[choice]));
    syslog(LOG_INFO, "choose as partner: %s", m.first.c_str());
    Connection connection = cn.init_peer(m);
    connection.check_remote_config(); 
    return connection;
}

void PeerManager::start(){
    std::cout << "starting all" << std::endl;
    std::thread srv {&PeerManager::serve, this};
    std::thread gsp {&PeerManager::gossip, this};
    srv.join();
    gsp.join();
}

void PeerManager::start_server(){
    std::cout << "starting only as server" << std::endl;
    std::thread srv {&PeerManager::serve, this};
    srv.join();
}

void PeerManager::start_client(){
    std::cout << "starting only as client" << std::endl;
    std::thread gsp {&PeerManager::gossip, this};
    gsp.join();
}

void PeerManager::serve(){
    
    syslog(LOG_INFO, "starting gossip server");

    cn.setup_listener(CONTEXT.peersettings.peaks_recon_port);
    std::vector<std::string> addresses;
    auto membership = CONTEXT.get<membership_t>("membership");
    std::transform(
        membership.begin(),
        membership.end(),
        std::back_inserter(addresses),
        (const std::string& (*)(const std::tuple<std::string, std::string, int>&))std::get<1>
    );

    for (;;){
        try{
            Connection connection = cn.acceptor(addresses);
            auto to_recover = connection.interact_with_client();
            fetch_elements(connection.get_peer(), to_recover);
        } catch (Bad_client & e){
            // error already logged by the connection manager
        } catch(std::exception & e){
            syslog(LOG_WARNING, "server terminated with exception: %s", e.what());
        }
    }
}

void PeerManager::fetch_elements(const Peer &peer, const std::vector<NTL::ZZ_p> &elems){

    syslog(LOG_DEBUG, "Should recover %d elements, starting double check!", int(elems.size()));
    std::vector<NTL::ZZ_p> elements;
    for (auto e: elems){
        if (!(PTREE.has_key(Utils::zz_to_hex(e))))
            elements.push_back(e);
    }

    int elements_size = elements.size();
    if (elements_size == 0){
        return;
    }
    int c_size = CONTEXT.peersettings.request_chunk_size;
    syslog(LOG_INFO, "Will recover %d certificates", int(elements_size));
    std::vector<std::string> keys;
    if (c_size > elements_size){
        syslog(LOG_DEBUG, "requesting all element at once!");
        keys = request_chunk(peer, elements);
    }else{
        for (int i=0; i <= elements_size/c_size; i++){
            syslog(LOG_DEBUG, "requesting chunk %d", (i+1));
            int start = i*c_size;
            int slice = c_size*(i+1);
            int end = (elements_size < slice) ? elements_size : slice;
            std::vector<NTL::ZZ_p> chunk;
            for (int j=start; j<end; j++) chunk.push_back(elements[j]);
            std::vector<std::string> new_keys = request_chunk(peer, chunk);
            keys.insert(keys.end(), new_keys.begin(), new_keys.end());
        }
    }
    syslog(LOG_DEBUG, "fetched %d keys from peer", int(keys.size()));
    if (CONTEXT.get<bool>("dryrun")){
        syslog(LOG_WARNING, "DRY RUN, will NOT insert certificates");
        return;
    }
    
    std::shared_ptr<IMPORT_DBManager> dbm = std::make_shared<IMPORT_DBManager>();

    for (auto &k: keys){
        try{
            pr::readPublicKeyPacket(k, dbm, true, false);
        }catch(...){
            // key unpacking failed
        }
    }
}

static size_t
StreamWriteCallback(char * buffer, size_t size, size_t nitems, std::ostream * stream)
{
    size_t realwrote = size * nitems;
    stream->write(buffer, static_cast<std::streamsize>(realwrote));
    if(!(*stream))
        realwrote = 0;

    return realwrote;
}


std::vector<std::string> PeerManager::request_chunk(const Peer &peer, const std::vector<NTL::ZZ_p> &chunk){
    Buffer buffer;
    buffer.write_int(chunk.size());
    for (auto zp: chunk){
        //hashquery are 16 byte long
        int hashquery_len = CONTEXT.peersettings.hashquery_len;
        buffer.write_int(hashquery_len);
        buffer.write_zz_p(zp, hashquery_len);
    }
    const std::string url = Utils::stringFormat("http://%s:%d/pks/hashquery", peer.hostname.c_str(), peer.port);
    syslog(LOG_DEBUG, "Requesting url %s", url.c_str());
    std::ostringstream response;

    curl_global_init(CURL_GLOBAL_ALL);
    CURL *curl = curl_easy_init();
    if(curl) {

	  struct curl_slist *headers=NULL;
      headers = curl_slist_append(headers, "Content-Type: sks/hashquery");
      
      curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buffer.c_str());
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, buffer.size());
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, StreamWriteCallback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
 
      CURLcode res_code = curl_easy_perform(curl);
      syslog(LOG_DEBUG, "Curl request performed");
      if(res_code != CURLE_OK)
        syslog(LOG_WARNING, "curl_easy_perform() failed: %s", curl_easy_strerror(res_code));
       
      long response_code;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
      if (response_code >= 400)
          throw std::runtime_error("Error in http response: " + response.str());
      curl_slist_free_all(headers);
      curl_easy_cleanup(curl);
      curl_global_cleanup();
    }

    //END
    Buffer res(response.str());
    int num_keys = res.read_int();
    std::vector<std::string> keys;
    for (int i=0; i < num_keys; i++)
        keys.push_back(res.read_string());
    return keys;

}

std::vector<NTL::ZZ_p> Connection::interact_with_client(){
    syslog(LOG_INFO, "Accepted remote peer %s, starting interaction...", peer.hostname.c_str());
    Recon_manager recon;
    std::shared_ptr<Pnode> root = PTREE.get_root();
    bitset newset(0);
    request_entry req = request_entry{.node = root, .key = newset};
    recon.push_request(req);
    while(!(recon.done())){
        if (recon.bottom_queue_empty()){
            request_entry request = recon.pop_request();
            recon.send_request(request);
        } else{
            bottom_entry bottom = recon.top_bottom();
            switch(bottom.state){
                case recon_state::FlushEnded:
                    {
                        recon.pop_bottom();
                        recon.toggle_flush(false);
                        break;
                    }
                case recon_state::Bottom:
                    {
                        bool ok = true;
                        Message* msg = read_message(ok);
                        if (ok){
                            recon.pop_bottom();
                            recon.handle_reply(msg, bottom.request);
                        } else {
                            if((recon.bottom_queue_size() > CONTEXT.peersettings.max_outstanding_recon_req) || 
                                (recon.request_queue_size() == 0)){
                                if (recon.is_flushing()){
                                    recon.pop_bottom();
                                    msg = read_message(ok);
                                    if (ok) recon.handle_reply(msg, bottom.request);
                                }
                                else{
                                    //flush
                                    send_bulk_messages(recon.get_flush_queue());
                                    recon.clean_queue();
                                }
                            } else {
                                request_entry req = recon.pop_request();
                                recon.send_request(req);
                            }
                        }
                        break;
                    }
            }
        }
    }
    Done* done = new Done;
    send_message(done);
    return recon.elements();
    //connection will be closed upon destruction
}

void PeerManager::gossip(){
    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(CONTEXT.msgsettings.P_SKS_STRING.c_str()));
    auto membership = CONTEXT.get<membership_t>("membership");
    for (;;){
        try{
            syslog(LOG_INFO, "starting gossip client");
            if (membership.size()) {
                Connection conn = choose_partner();
                auto to_recover = conn.client_recon();
                fetch_elements(conn.get_peer(), to_recover);
            }
        } catch (std::exception &e){
            syslog(LOG_NOTICE, "%s", e.what());
            //connection automatically closed
        }
        syslog(LOG_INFO, "going to sleep...");
        std::this_thread::sleep_for(std::chrono::seconds{CONTEXT.peersettings.gossip_interval});
        syslog(LOG_INFO, "...resuming gossip");
    }
}

std::vector<NTL::ZZ_p> Connection::client_recon(){
    syslog(LOG_INFO, "choosen partner %s", peer.hostname.c_str());
    zpset response;
    std::vector<Message*> pending;
    std::vector<NTL::ZZ_p> empty;

    int n=0; 

    for(;;){
        Communication comm;
        //comm.messages.empty();
        comm.send=false;
        comm.status=Communication_status::NONE;

        // fetch request + craft response
        bool ok = true;
        Message* msg = read_message(ok);
        if (!ok) throw std::runtime_error("Sync Failed");
        syslog(LOG_DEBUG, "handling message %d", msg->type);
        switch (msg->type){
            case Msg_type::ReconRequestPoly:{
                //ReconRequestPoly
                comm = request_poly_handler((ReconRequestPoly*) msg);
                delete ((ReconRequestPoly*) msg);
                break;
                   }
            case Msg_type::ReconRequestFull:{
                //Request Full
                comm = request_full_handler((ReconRequestFull*) msg); 
                delete ((ReconRequestFull*) msg);
                break;
                   }
            case Msg_type::Elements:{
                //elements
                comm.elements = ((Elements *) msg)->elements;
                delete ((Elements *) msg);
                break;
                   }
            case Msg_type::Done:{
                //done
                comm.status = Communication_status::DONE;
                break;
                   }
            case Msg_type::Flush:{
                //flush
                comm.send = true;
                break;
                   }
            default:
                //???
                syslog(LOG_WARNING, "ERROR, UNKNOWN MESSAGE");
                comm.status = Communication_status::ERROR;
        }
        n += comm.elements.size();
        response.add(comm.elements.elements());
        syslog(LOG_DEBUG, "current value of n: %d", n);

        if (comm.status == Communication_status::ERROR){
            Error* error_msg = new Error;
            error_msg->type = Msg_type::Error;
            error_msg->text = "step_error";
            send_message(error_msg);
            return empty;
        } 
        else if ((comm.status == Communication_status::DONE) || (n >= CONTEXT.peersettings.max_recover_size)){
                //connection automatically closed
                return response.elements();
        }
        pending.insert(pending.end(), comm.messages.begin(), comm.messages.end());
        if (comm.send){
            // send response
            send_bulk_messages(pending);
            pending.clear();
        }
    }
    return empty;
}

std::pair<std::vector<NTL::ZZ_p>,std::vector<NTL::ZZ_p>> 
    Connection::solve(
        const std::vector<NTL::ZZ_p> &r_samples,
        const int r_size,
        const std::vector<NTL::ZZ_p> &l_samples,
        const int l_size,
        const std::vector<NTL::ZZ_p> &points){
    std::vector<NTL::ZZ_p> values;
    for (size_t i=0; i < r_samples.size(); i++)
        values.push_back(r_samples[i]/l_samples[i]);
    int diff = r_size - l_size;
    size_t size_diff = (diff > 0) ? diff : (- diff);

    //Interpolation
    //Need to go through
    //all the steps because
    //we need the Lagrange form of
    //the interpolating polynomial
    if (size_diff > values.size()-1){
        syslog(LOG_DEBUG, "Could not interpolate because size_diff (%d) > size of values(%d)!", (int)size_diff, (int)values.size());
        throw solver_exception();
        }
    int mbar = CONTEXT.treesettings.mbar;
    if ((mbar + size_diff)%2 != 0) mbar--;
    int ma = (mbar + size_diff)/2;
    int mb = (mbar - size_diff)/2;
    NTL::Mat<NTL::ZZ_p> matrix;
    matrix.SetDims(mbar,  mbar+1);
    for (int i=0; i<mbar; i++){
        NTL::ZZ_p sum(1);
        NTL::ZZ_p ki = points[i];
        NTL::ZZ_p fi = values[i];
        for (int j=0; j<ma; j++){
            matrix.put(i, j, sum);
            sum = sum * ki;
        }
        NTL::ZZ_p ki_ma = sum;
        negate(sum, fi);
        for (int j=ma; j<mbar; j++){
            matrix.put(i, j, sum);
            sum *= ki;
        }
        NTL::ZZ_p fi_ki_mb;
        negate(fi_ki_mb, sum);
        matrix.put(i, mbar, fi_ki_mb - ki_ma);
    }

    /*
    //gauss form
    gauss(matrix);

    //normalization
    
    int last;
    NTL::ZZ_p scmult,sval,v;
    for (int i=matrix.NumRows()-1; i>=0; i--){
        NTL::ZZ_p lead = matrix.get(i,i);
        if (lead != 1){
            for (int j=i; j<matrix.NumCols(); j++){
                NTL::ZZ_p v = matrix.get(i,j);
                matrix.put(i,j,v * pow(lead, );
        }
        }
    }
    */
	int i_max = 1;
    int h = 1; /* Initialization of the pivot row */
    int k = 1; /* Initialization of the pivot column */
    int i=1;
    NTL::ZZ_p f(0);  

    while (h <= matrix.NumRows() and k <= matrix.NumCols()){
      /* Find the k-th pivot: */
        NTL::ZZ_p save = matrix(h,k);
        for(int i = h; i < matrix.NumRows(); i++){
            if(rep(save) - rep(matrix(i,k)) > 0){
                save = matrix(i,k);
                i_max = i;
            }
        }
        if (matrix(i_max, k) == 0){
          /* No pivot in this column, pass to next column */
          k = k+1;
        }
        else{
            NTL::Vec<NTL::ZZ_p> swa = matrix(h);
            NTL::Vec<NTL::ZZ_p> swo = matrix(i_max);
            for (int z=0; z<=matrix.NumCols()-1; z++){
                matrix.put(h-1, z, swo[z]); 
                matrix.put(i_max-1, z, swa[z]);
            }
           /* Do for all rows below pivot: */
           for (i = h + 1; i < matrix.NumRows(); i++){
              f = matrix(i, k) / matrix(h, k);
              /* Fill with zeros the lower part of pivot column: */
              matrix.put(i-1, k-1, NTL::ZZ_p(0));
              /* Do for all remaining elements in current row: */
              for (int j = k + 1; j < matrix.NumCols(); j++)
                 matrix.put(i-1, j-1, matrix(i, j) - matrix(h, j) * f);
           }
           /* Increase pivot row and column */
           h = h+1; 
           k = k+1;
        }
}


    //back substitute
    int last;
    NTL::ZZ_p scmult,sval,v;
    
    for (int j=matrix.NumRows()-1; j>0; j--){
        last = matrix.NumRows()-1;
        for (int j2=j-1; j2>=0; j2--){
            scmult = matrix.get(j2,j);
            for (int i=last; i<matrix.NumCols(); i++){
                sval = matrix.get(j, i);
                if (sval != 0){
                    v = matrix.get(j2, i);
                    v -= sval * scmult;
                    matrix.put(j2,i,v);
                    }
            }
            matrix.put(j2,j,NTL::ZZ_p(0));
        }
    }

    
    NTL::ZZ_pX a_poly;
    NTL::ZZ_pX b_poly;
    for (int i=0; i< ma; i++)
        SetCoeff(a_poly, i, matrix.get(i, mbar));
    SetCoeff(a_poly, ma);
    for (int i=0; i<mb; i++)
        SetCoeff(b_poly, i, matrix.get(i+ma, mbar));
    SetCoeff(b_poly, mb);
    NTL::ZZ_pX g_poly = GCD(a_poly, b_poly);
    NTL::ZZ_pX num = a_poly/g_poly;
    NTL::ZZ_pX den = b_poly/g_poly;

    NTL::ZZ_p last_point = points.back();
    NTL::ZZ_p num_val = eval(num,last_point);
    NTL::ZZ_p den_val = eval(den,last_point);
    NTL::ZZ_p last_value = values.back();
    if ((last_value != num_val/den_val) ||
            DetIrredTest(num) ||
            DetIrredTest(den))
        throw low_mbar_exception();
    NTL::Vec<NTL::ZZ_p> num_factor = FindRoots(num);
    NTL::Vec<NTL::ZZ_p> den_factor = FindRoots(den);
    std::ostringstream os;
    os << num_factor;
    os << std::endl;
    os << den_factor;
    os << std::endl;
    std::vector<NTL::ZZ_p> stl_num_factor, stl_den_factor;

    for (auto e: num_factor)
        stl_num_factor.push_back(e);
    for (auto e: den_factor)
        stl_den_factor.push_back(e);
    return std::make_pair(stl_num_factor, stl_den_factor);
}



Communication Connection::request_poly_handler(ReconRequestPoly* req){
    int r_size = req->size;
    std::vector<NTL::ZZ_p> r_samples = req->samples;
    bitset key = req->prefix;
    std::shared_ptr<Pnode> node = PTREE.node(key);
    std::vector<NTL::ZZ_p> l_samples = node->get_node_svalues();
    int l_size = node->get_num_elements();
    std::vector<NTL::ZZ_p> elements;
    std::vector<NTL::ZZ_p> local_elements, remote_elements;

    try{
        std::tie(local_elements, remote_elements) = solve(r_samples, r_size, l_samples, l_size, CONTEXT.treesettings.points);
    }
    //catch (solver_exception& e){
    catch (std::exception &e){
        if ((strncmp(e.what(),"low_mbar",8)) && 
                    (
                     (node->is_leaf()) ||
                     (node->get_num_elements() < CONTEXT.treesettings.ptree_thresh_mult * CONTEXT.treesettings.mbar)
                     )
            ){
                elements = node->elements();
                Communication newcomm;
                FullElements* full_elements = new FullElements;
                full_elements->elements.add(elements); 
                newcomm.messages.push_back(full_elements);
                return newcomm;
        }
        else {
            Communication newcomm;
            SyncFail* fail = new SyncFail;
            newcomm.messages.push_back(fail);
            return newcomm;
        }
    }
    Communication newcomm;
    zpset remote_elements_set(remote_elements);
    zpset local_elements_set(local_elements);
    syslog(LOG_INFO, "found local needs %lu", remote_elements.size());
    syslog(LOG_INFO, "found remote needs %lu", local_elements.size());
    newcomm.elements = remote_elements_set;
    Elements* m_elements = new Elements;
    m_elements->elements = local_elements_set; 
    newcomm.messages.push_back(m_elements);
    return newcomm;
}

Communication Connection::request_full_handler(ReconRequestFull* req){
    zpset remote_set(req->elements);
    Communication newcomm;
    std::shared_ptr<Pnode> node;
    try{
        node = PTREE.node(req->prefix);
    } catch (std::exception& e){
        newcomm.status = Communication_status::ERROR;
        return newcomm;
    }
    zpset local_set(node->elements());
    std::vector<NTL::ZZ_p> local_needs, remote_needs;
    std::tie(local_needs, remote_needs) = remote_set.symmetric_difference(local_set); 

    newcomm.elements = local_needs;
    Elements* m_elements = new Elements;
    m_elements->elements = remote_needs;
    newcomm.messages.push_back(m_elements);
    return newcomm;
}

}
}
