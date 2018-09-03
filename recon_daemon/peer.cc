#include "peer.h"

Peer::Peer(Ptree new_tree){
    tree = new_tree;
    cn = Connection_Manager();
    std::ifstream f("membership");
    std::string addr;
    int port;
    while(f >> addr >> port){
        membership.push_back(std::make_pair(addr, port));
    }
    if (membership.size() == 0){
        g_logger.log(Logger_level::WARNING, "Membership file is empty! Stopping Recon");
        exit(0);
    }else{
        for (peertype peer : membership)
            g_logger.log(Logger_level::DEBUG, "Membership entry: " + peer.first);
    }
}

peertype Peer::choose_partner(){
    
    int choice = Utils::get_random(membership.size());
    peertype peer = membership[choice];
    g_logger.log(Logger_level::DEBUG, "choose as partner: " + peer.first);
    int http_port = cn.init_peer(peer);
    return std::make_pair(peer.first, http_port);
}

void Peer::start(){
    //std::thread srv {&Peer::serve, this};
    std::thread gsp {&Peer::gossip, this};
    //srv.join();
    gsp.join();
}

void Peer::serve(){
    
    g_logger.log(Logger_level::DEBUG, "starting gossip server");

    cn.setup_listener(recon_settings.peaks_recon_port);
    std::vector<std::string> addresses;
    std::transform(membership.begin(), membership.end(), std::back_inserter(addresses), (const std::string& (*)(const peertype&))std::get<0>);

    g_logger.log(Logger_level::DEBUG, "parsed membership, starting acceptor loop");
    for (;;){
        g_logger.log(Logger_level::DEBUG, "server loop");
        peertype remote_peer;
        bool check;
        std::tie(check, remote_peer) = cn.acceptor(addresses);
        if (check){
            g_logger.log(Logger_level::DEBUG, "Accepted remote peer " + remote_peer.first + ", starting interaction...");
            //std::thread srv_c {&Peer::interact_with_client, this, remote_peer};
            try{
                interact_with_client(remote_peer);
            }catch(std::exception &e){
                g_logger.log(Logger_level::DEBUG, std::string(e.what()));
            }
        }
    }
}

void Peer::fetch_elements(peertype peer, std::vector<NTL::ZZ_p> elems){

    g_logger.log(Logger_level::DEBUG, "Should recover " + std::to_string(elems.size()) + " elements");
    g_logger.log(Logger_level::DEBUG, "Some sample: ");
    std::ostringstream os;
    for (int i=0; i<5; i++)
        os << Utils::ZZp_to_bitstring(elems[i]) << "\t";
    g_logger.log(Logger_level::DEBUG, os.str());
    std::vector<NTL::ZZ_p> elements;
    for (auto e: elems){
        //if (!(tree.has_key(Utils::ZZp_to_bitstring(e))))
            elements.push_back(e);
    }

    int elements_size = elements.size();
    if (elements_size == 0){
        g_logger.log(Logger_level::DEBUG, "No elements to recover!");
        return;
    }
    int c_size = recon_settings.request_chunk_size;
    g_logger.log(Logger_level::DEBUG, "Elements to recover: " + std::to_string(elements_size));
    std::vector<std::string> keys;
    if (c_size > elements_size){
        g_logger.log(Logger_level::DEBUG, "requesting all element at once!");
        keys = request_chunk(peer, elements);
    }else{
        for (int i=0; i <= elements_size/c_size; i++){
            g_logger.log(Logger_level::DEBUG, "requesting chunk " + std::to_string(i+1));
            int start = i*c_size;
            int slice = c_size*(i+1);
            int end = (elements_size < slice) ? elements_size : slice;
            std::vector<NTL::ZZ_p> chunk;
            for (int j=start; j<end; j++) chunk.push_back(elements[j]);
            std::vector<std::string> new_keys = request_chunk(peer, chunk);
            keys.insert(keys.end(), new_keys.begin(), new_keys.end());
        }
    }
    g_logger.log(Logger_level::DEBUG, "fetched " + std::to_string(keys.size()) + " keys from peer!");
    std::vector<std::string> hashes = dump_import(keys);
    g_logger.log(Logger_level::DEBUG, "inserted keys into DB, (gained " +std::to_string(hashes.size())  + " hashes)");
    for (auto hash: hashes)
        tree.insert(hash);
    g_logger.log(Logger_level::DEBUG, "inserted hashes into ptree");
}

std::vector<std::string> Peer::request_chunk(peertype peer, std::vector<NTL::ZZ_p> chunk){
    Buffer buffer;
    buffer.write_int(chunk.size());
    for (auto zp: chunk){
        //hashquery are 16 byte long
        int hashquery_len = recon_settings.hashquery_len;
        buffer.write_int(hashquery_len);
        buffer.write_zz_p(zp, hashquery_len);
    }
    std::string url = std::string("http://") + peer.first + std::string(":") + std::to_string(peer.second) + std::string("/pks/hashquery");
    g_logger.log(Logger_level::DEBUG, "Requesting url "+url);
    curlpp::Cleanup cleaner;
    curlpp::Easy request;
    request.setOpt(new curlpp::options::Url(url));
    std::list<std::string> header;
    std::ostringstream response;
    //header.push_back("Content-Length: " + std::to_string(buffer.size()));
    header.push_back("Content-Type: sks/hashquery");
    request.setOpt(new curlpp::options::HttpHeader(header));
    request.setOpt(new curlpp::options::PostFields(buffer.to_str()));
    request.setOpt(new curlpp::options::PostFieldSize(buffer.size()));
    request.setOpt(new curlpp::options::WriteStream(&response));
    request.perform();
    g_logger.log(Logger_level::DEBUG, "Curlpp request performed");
    Buffer res(response.str());
    int num_keys = res.read_int();
    std::vector<std::string> keys;
    for (int i=0; i < num_keys; i++)
        keys.push_back(res.read_string());
    return keys;
}

void Peer::interact_with_client(peertype remote_peer){
    Recon_manager recon = Recon_manager(cn);
    Pnode* root = tree.get_root();
    bitset newset(0);
    request_entry req = request_entry{.node = root, .key = newset};
    recon.push_request(req);
    while(!(recon.done())){
        g_logger.log(Logger_level::DEBUG, "entering server response loop");
        if (recon.bottom_queue_empty()){
            g_logger.log(Logger_level::DEBUG, "bottom queue empty: generating initial request");
            request_entry request = recon.pop_request();
            recon.send_request(request);
        } else{
            g_logger.log(Logger_level::DEBUG, "fetching request from bottom queue");
            bottom_entry bottom = recon.top_bottom();
            g_logger.log(Logger_level::DEBUG, "Bottom State: " + std::to_string(bottom.state));
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
                            g_logger.log(Logger_level::DEBUG, "trying async operation");
                            msg = cn.read_message_async();
                            g_logger.log(Logger_level::DEBUG, "async operation succesfully fetched message");
                            recon.pop_bottom();
                            recon.handle_reply(msg, bottom.request);
                        } catch(std::invalid_argument &e){
                            g_logger.log(Logger_level::DEBUG, "no message on async operation");
                            if((recon.bottom_queue_size() > recon_settings.max_outstanding_recon_req) || 
                                (recon.request_queue_size() == 0)){
                                if (recon.is_flushing()){
                                    recon.pop_bottom();
                                    try{
                                        cn.set_timeout(3);
                                        msg = cn.read_message();
                                        recon.handle_reply(msg, bottom.request);
                                    }catch(...){
                                    }
                                }
                                else{
                                    g_logger.log(Logger_level::DEBUG, "recon flushing");
                                    recon.flush_queue();
                                }
                            } else {
                                request_entry req = recon.pop_request();
                                recon.send_request(req);
                            }
                        } catch(std::exception &e){
                            g_logger.log(Logger_level::DEBUG, "Unexpected catch " + std::string(e.what()));
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
    for (;;){
        try{
            g_logger.log(Logger_level::DEBUG, "starting gossip client");
            peertype peer = choose_partner();
            g_logger.log(Logger_level::DEBUG, "choosen partner " + peer.first);
            client_recon(peer);
        } catch (connection_exception &e){
            g_logger.log(Logger_level::DEBUG, std::string(e.what()));
        }
        g_logger.log(Logger_level::DEBUG, "going to sleep...");
        std::this_thread::sleep_for(std::chrono::seconds{recon_settings.gossip_interval});
        g_logger.log(Logger_level::DEBUG, "...resuming gossip");
    }
}

void Peer::client_recon(peertype peer){
    g_logger.log(Logger_level::DEBUG, "Starting recon as client with peer " + peer.first + ", http_port " + std::to_string(peer.second));
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
        g_logger.log(Logger_level::DEBUG, "prepare to handle message type" + std::to_string(msg->type));
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
                g_logger.log(Logger_level::DEBUG, "comm samples size: " + std::to_string(comm.samples.size()));
                break;
                   }
            case Msg_type::Elements:{
                //elements
                comm.samples = ((Elements *) msg)->samples;
                delete ((Elements *) msg);
                g_logger.log(Logger_level::DEBUG, std::to_string(comm.samples.size()));
                break;
                   }
            case Msg_type::Done:{
                //done
                g_logger.log(Logger_level::DEBUG, "DONE RECON!");
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
                g_logger.log(Logger_level::WARNING, "ERROR, UNKNOWN MESSAGE");
                comm.status = Communication_status::ERROR;
        }
        n += comm.samples.size();
        g_logger.log(Logger_level::DEBUG, "current value of n: " + std::to_string(n));

        if (comm.status == Communication_status::ERROR){
            Error* error_msg = new Error;
            error_msg->type = Msg_type::Error;
            error_msg->text = "step_error";
            cn.send_message(error_msg);
            return;
        } 
        else if ((comm.status == Communication_status::DONE) || (n >= recon_settings.max_recover_size)){
                fetch_elements(peer, response.elements());
                cn.close_connection();
                return;
        }
        for (auto m: comm.messages)
            g_logger.log(Logger_level::DEBUG, "Adding Message type " + std::to_string(m->type));
        g_logger.log(Logger_level::DEBUG, "Resulting communication has " + std::to_string(comm.messages.size()) + " messages");
        pending.insert(pending.end(), comm.messages.begin(), comm.messages.end());
        g_logger.log(Logger_level::DEBUG, "There are now " + std::to_string(pending.size()) + " pending messages");
        if (comm.send){
            // send response
            g_logger.log(Logger_level::DEBUG, "sending pending messages");
            cn.send_bulk_messages(pending);
            pending.clear();
        }
        response.add(comm.samples.elements());
    }
}

std::pair<std::vector<NTL::ZZ_p>,std::vector<NTL::ZZ_p>> Peer::solve(std::vector<NTL::ZZ_p> r_samples, int r_size, std::vector<NTL::ZZ_p> l_samples, int l_size, std::vector<NTL::ZZ_p> points){
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
        g_logger.log(Logger_level::WARNING, "Could not interpolate because size_diff > size of values!");
        throw solver_exception();
        }
    int mbar = recon_settings.mbar;
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
    //gauss for
    gauss(matrix);
    g_logger.log(Logger_level::DEBUG, "Finished gauss form");

    //normalization
    
    int last;
    NTL::ZZ_p scmult,sval,v;
    for (int i=matrix.NumRows()-1; i>=0; i--){
        NTL::ZZ_p lead = matrix.get(i,i);
        if (lead != 1){
            for (int j=i; j<matrix.NumCols(); j++){
                NTL::ZZ_p v = matrix.get(i,j);
                matrix.put(i,j,v/lead);
        }
        }
    }
    g_logger.log(Logger_level::DEBUG, "Finished gauss form and normalizing");

    //back substitute
    
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

    g_logger.log(Logger_level::DEBUG, "applied back substitute");
    
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

    g_logger.log(Logger_level::DEBUG, "Calculated num and den");
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
    g_logger.log(Logger_level::DEBUG, "Find roots done!\n" + os.str());
    std::vector<NTL::ZZ_p> stl_num_factor, stl_den_factor;

    for (auto e: num_factor)
        stl_num_factor.push_back(e);
    for (auto e: den_factor)
        stl_den_factor.push_back(e);
    return std::make_pair(stl_num_factor, stl_den_factor);
}


Communication Peer::request_poly_handler(ReconRequestPoly* req){
    int r_size = req->size;
    std::vector<NTL::ZZ_p> points = tree.get_points();
    std::vector<NTL::ZZ_p> r_samples = req->samples;
    bitset key = req->prefix;
    std::string prefix_str = key.to_string();
    g_logger.log(Logger_level::DEBUG, "ReconRequestPoly for node: " + prefix_str);
    Pnode* node = tree.node(key);
    std::vector<NTL::ZZ_p> l_samples = node->get_node_svalues();
    int l_size = node->get_num_elements();
    std::vector<NTL::ZZ_p> elements;
    std::vector<NTL::ZZ_p> local_samples, remote_samples;

    try{
        std::tie(local_samples, remote_samples) = solve(r_samples, r_size, l_samples, l_size, points);
        g_logger.log(Logger_level::DEBUG, "solved interpolation succesfully!");
    }
    //catch (solver_exception& e){
    catch (std::exception &e){
        g_logger.log(Logger_level::DEBUG, "catched logger exception: " + std::string(e.what()));
        if ((strncmp(e.what(),"low_mbar",8)) && 
                    (
                     (node->is_leaf()) ||
                     (node->get_num_elements() < recon_settings.ptree_thresh_mult * recon_settings.mbar)
                     )
            ){
                g_logger.log(Logger_level::DEBUG, "Preparing to send FullElements request");
                elements = node->elements();
                Communication newcomm;
                FullElements* full_elements = new FullElements;
                full_elements->samples.add(elements); 
                newcomm.messages.push_back(full_elements);
                return newcomm;
        }
        else {
            g_logger.log(Logger_level::DEBUG, "Preparing to send Syncfail");
            Communication newcomm;
            SyncFail* fail = new SyncFail;
            newcomm.messages.push_back(fail);
            return newcomm;
        }
    }
    Communication newcomm;
    zset remote_elements(remote_samples);
    zset local_elements(local_samples);
    newcomm.samples = remote_elements;
    Elements* m_elements = new Elements;
    m_elements->samples = local_elements; 
    newcomm.messages.push_back(m_elements);
    return newcomm;
}

Communication Peer::request_full_handler(ReconRequestFull* req){
    Myset<NTL::ZZ_p> remote_set(req->samples);
    Myset<NTL::ZZ_p> local_set;
    Communication newcomm;
    try{
        Pnode* node = tree.node(req->prefix);
        local_set.add(node->elements());
    } catch (std::exception& e){
        newcomm.status = Communication_status::ERROR;
        return newcomm;
    }
    std::string prefix_str = req->prefix.to_string();
    g_logger.log(Logger_level::DEBUG, "ReconRequestFull for node: " + prefix_str);
    std::vector<NTL::ZZ_p> local_needs, remote_needs;
    std::tie(local_needs, remote_needs) = remote_set.symmetric_difference(local_set); 
    newcomm.samples = local_needs;
    Elements* m_elements = new Elements;
    m_elements->samples = remote_needs;
    newcomm.messages.push_back(m_elements);
    return newcomm;
}
