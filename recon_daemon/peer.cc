#include "peer.h"

Peer::Peer(Ptree &new_tree, const Recon_config & peer_settings, const Connection_config & conn_settings, ReconImporter &di_, const Message_config & conf):
    cn(conn_settings),
    tree(std::move(new_tree)),
    settings(peer_settings),
    di (di_),
    msg_config(conf)
{
    std::ifstream f(settings.membership_config);
    std::string addr;
    int port;
    while(f >> addr >> port){
        membership.push_back(std::make_pair(addr, port));
    }
    if (membership.size() == 0){
        syslog(LOG_WARNING, "Membership file provided is empty!");
        exit(0);
    }
}

peertype Peer::choose_partner(){
    
    int choice = RECON_Utils::get_random(membership.size());
    peertype peer = membership[choice];
    syslog(LOG_DEBUG, "choose as partner: %s", peer.first.c_str());
    int http_port = cn.init_peer(peer);
    return std::make_pair(peer.first, http_port);
}

void Peer::start(){
    std::cout << "starting all" << std::endl;
    std::thread srv {&Peer::serve, this};
    std::thread gsp {&Peer::gossip, this};
    srv.join();
    gsp.join();
}

void Peer::start_server(){
    std::cout << "starting only as server" << std::endl;
    std::thread srv {&Peer::serve, this};
    srv.join();
}

void Peer::start_client(){
    std::cout << "starting only as client" << std::endl;
    std::thread gsp {&Peer::gossip, this};
    gsp.join();
}

void Peer::serve(){
    
    syslog(LOG_DEBUG, "starting gossip server");

    cn.setup_listener(settings.peaks_recon_port);
    std::vector<std::string> addresses;
    std::transform(membership.begin(), membership.end(), std::back_inserter(addresses), (const std::string& (*)(const peertype&))std::get<0>);

    for (;;){
        peertype remote_peer;
        try{
            remote_peer = cn.acceptor(addresses);
            syslog(LOG_DEBUG, "Accepted remote peer %s, starting interaction...", remote_peer.first.c_str());
            interact_with_client(remote_peer);
        } catch (Bad_client & e){
            // error already logged by the connection manager
        } catch(std::exception & e){
            syslog(LOG_WARNING, "server terminated with exception: %s", e.what());
        }
    }
}

void Peer::fetch_elements(const peertype &peer, const std::vector<NTL::ZZ_p> &elems){

    syslog(LOG_DEBUG, "Should recover %d elements, starting double check!", int(elems.size()));
    std::vector<NTL::ZZ_p> elements;
    for (auto e: elems){
        if (!(tree.has_key(RECON_Utils::zz_to_hex(e))))
            elements.push_back(e);
    }

    int elements_size = elements.size();
    if (elements_size == 0){
        return;
    }
    int c_size = settings.request_chunk_size;
    syslog(LOG_DEBUG, "Will recover: %d", int(elements_size));
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
    if (settings.dry_run){
        syslog(LOG_WARNING, "DRY RUN, exiting without inserting certificates");
        return;
    }
    std::vector<std::string> hashes = di.import(keys);
    if (hashes.size() != elements.size()){
        syslog(LOG_WARNING, "number of recovered keys does not match number of hashes recovered!");
    }
    /*
    for (auto hash: elements)
        if (std::find(hashes.begin(), hashes.end(), RECON_Utils::zz_to_hex(hash)) == hashes.end())
            */
    tree.update(hashes);
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


std::vector<std::string> Peer::request_chunk(const peertype &peer, const std::vector<NTL::ZZ_p> &chunk){
    Buffer buffer;
    buffer.write_int(chunk.size());
    for (auto zp: chunk){
        //hashquery are 16 byte long
        int hashquery_len = settings.hashquery_len;
        buffer.write_int(hashquery_len);
        buffer.write_zz_p(zp, hashquery_len);
    }
    const std::string url = std::string("http://") + peer.first + std::string(":") + std::to_string(peer.second) + std::string("/pks/hashquery");
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

void Peer::interact_with_client(peertype &remote_peer){
    Recon_manager recon = Recon_manager(cn, msg_config);
    std::shared_ptr<Pnode> root = tree.get_root();
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
                        Message* msg;
                        try{
                            msg = cn.read_message_async();
                            recon.pop_bottom();
                            recon.handle_reply(msg, bottom.request);
                        } catch(std::invalid_argument &e){
                            if((recon.bottom_queue_size() > settings.max_outstanding_recon_req) || 
                                (recon.request_queue_size() == 0)){
                                if (recon.is_flushing()){
                                    recon.pop_bottom();
                                    try{
                                        msg = cn.read_message_async();
                                        recon.handle_reply(msg, bottom.request);
                                    }catch(...){
                                    }
                                }
                                else{
                                    recon.flush_queue();
                                }
                            } else {
                                request_entry req = recon.pop_request();
                                recon.send_request(req);
                            }
                        } catch(std::exception &e){
                            syslog(LOG_DEBUG, "Unexpected catch %s", e.what());
                        }
                        break;
                    }
            }
        }
    }
    Done* done = new Done;
    cn.send_message(done);
    fetch_elements(remote_peer, recon.elements());
    cn.close_connection();
}

void Peer::gossip(){
    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(msg_config.P_SKS_STRING.c_str()));
    for (;;){
        try{
            syslog(LOG_DEBUG, "starting gossip client");
            peertype peer = choose_partner();
            syslog(LOG_DEBUG, "choosen partner %s", peer.first.c_str());
            client_recon(peer);
        } catch (std::exception &e){
            syslog(LOG_DEBUG, "%s", e.what());
            cn.close_connection();
        }
        syslog(LOG_DEBUG, "going to sleep...");
        std::this_thread::sleep_for(std::chrono::seconds{settings.gossip_interval});
        syslog(LOG_DEBUG, "...resuming gossip");
    }
}

void Peer::client_recon(const peertype &peer){
    zset response;
    std::vector<Message*> pending;

    int n=0; 

    for(;;){
        Communication comm;
        //comm.messages.empty();
        comm.send=false;
        comm.status=Communication_status::NONE;

        // fetch request + craft response
       
        Message* msg = cn.read_message();
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
            cn.send_message(error_msg);
            return;
        } 
        else if ((comm.status == Communication_status::DONE) || (n >= settings.max_recover_size)){
                fetch_elements(peer, response.elements());
                cn.close_connection();
                return;
        }
        pending.insert(pending.end(), comm.messages.begin(), comm.messages.end());
        if (comm.send){
            // send response
            cn.send_bulk_messages(pending);
            pending.clear();
        }
    }
}

std::pair<std::vector<NTL::ZZ_p>,std::vector<NTL::ZZ_p>> Peer::solve(const std::vector<NTL::ZZ_p> &r_samples, const int r_size, const std::vector<NTL::ZZ_p> &l_samples, const int l_size, const std::vector<NTL::ZZ_p> &points){
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
    int mbar = tree.get_settings().mbar;
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


Communication Peer::request_poly_handler(ReconRequestPoly* req){
    int r_size = req->size;
    std::vector<NTL::ZZ_p> r_samples = req->samples;
    bitset key = req->prefix;
    std::string prefix_str = key.to_string();
    std::shared_ptr<Pnode> node = tree.node(key);
    std::vector<NTL::ZZ_p> l_samples = node->get_node_svalues();
    int l_size = node->get_num_elements();
    std::vector<NTL::ZZ_p> elements;
    std::vector<NTL::ZZ_p> local_elements, remote_elements;

    try{
        std::tie(local_elements, remote_elements) = solve(r_samples, r_size, l_samples, l_size, tree.get_settings().points);
    }
    //catch (solver_exception& e){
    catch (std::exception &e){
        if ((strncmp(e.what(),"low_mbar",8)) && 
                    (
                     (node->is_leaf()) ||
                     (node->get_num_elements() < tree.get_settings().ptree_thresh_mult * tree.get_settings().mbar)
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
    zset remote_elements_set(remote_elements);
    zset local_elements_set(local_elements);
    newcomm.elements = remote_elements_set;
    Elements* m_elements = new Elements;
    m_elements->elements = local_elements_set; 
    newcomm.messages.push_back(m_elements);
    return newcomm;
}

Communication Peer::request_full_handler(ReconRequestFull* req){
    Myset<NTL::ZZ_p> remote_set(req->elements);
    Myset<NTL::ZZ_p> local_set;
    Communication newcomm;
    try{
        std::shared_ptr<Pnode> node = tree.node(req->prefix);
        local_set.add(node->elements());
    } catch (std::exception& e){
        newcomm.status = Communication_status::ERROR;
        return newcomm;
    }
    std::string prefix_str = req->prefix.to_string();
    std::vector<NTL::ZZ_p> local_needs, remote_needs;
    std::tie(local_needs, remote_needs) = remote_set.symmetric_difference(local_set); 

    newcomm.elements = local_needs;
    Elements* m_elements = new Elements;
    m_elements->elements = remote_needs;
    newcomm.messages.push_back(m_elements);
    return newcomm;
}
