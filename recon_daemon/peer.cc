#include "peer.h"

Peer::Peer(Ptree new_tree){
    std::cout << "current modulus " << ZZ_p::modulus() << std::endl;
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
    cn.init(peer);
    return peer;
}

void Peer::start(){
    //std::thread srv {&Peer::serve, this};
    std::thread gsp {&Peer::gossip, this};
    //srv.join();
    gsp.join();
}

void Peer::serve(){
    
    g_logger.log(Logger_level::DEBUG, "starting gossip server");
    cn.setup_listener(Recon_settings::peaks_port);
    std::vector<std::string> addresses;
    std::transform(membership.begin(), membership.end(), std::back_inserter(addresses), (const std::string& (*)(const peertype&))std::get<0>);
    for (;;){
        g_logger.log(Logger_level::DEBUG, "starting acceptor loop");
        bool check;
        peertype remote_peer;
        std::tie(check, remote_peer) = cn.acceptor(addresses);
        if(check){
            std::thread srv_c {&Peer::serve_client, this, remote_peer};
        }
    }
}

void Peer::serve_client(peertype peer){
    Vec<ZZ_p> elements = interact_with_client();
    fetch_elements(peer, elements);
}

void Peer::fetch_elements(peertype peer, Vec<ZZ_p> elements){
    int elements_size = elements.length();
    int c_size = Recon_settings::request_chunk_size;
    if (c_size > elements_size){
        request_chunk(peer, elements);
    }
    for (int i=0; i <= elements_size/c_size; i++){
        int start = i*c_size;
        int end = min(elements_size, c_size*(i+1));
        Vec<ZZ_p> chunk;
        for (int j=start; j<end; j++) chunk.append(elements[j]);
        request_chunk(peer, chunk);
    }
}

void Peer::request_chunk(peertype peer, Vec<ZZ_p> chunk){
    Buffer buffer;
    buffer.write_int(chunk.length());
    for (auto zp: chunk){
        //hashquery are 16 byte long
        buffer.write_int(16);
        buffer.write_zz_p(zp);
    }
    std::string url = std::string("http://") + peer.first + std::string("/pks/hashquery");
    curlpp::Cleanup cleaner;
    curlpp::Easy request;
    request.setOpt(new curlpp::options::Url(url));
    std::list<std::string> header;
    std::ostringstream response;
    header.push_back("Content-Length: " + std::to_string(buffer.size()));
    request.setOpt(new curlpp::options::HttpHeader(header));
    request.setOpt(new curlpp::options::PostFields(buffer.to_str()));
    request.setOpt(new curlpp::options::WriteStream(&response));
    request.perform();
    Buffer res(response.str());
    int num_keys = res.read_int();
    std::vector<std::string> keys;
    for (int i=0; i < num_keys; i++)
        keys.push_back(res.read_string());
    std::vector<std::string> hashes = dump_import(keys);
    res.read_bytes(2); //read last 2 bytes
    tree.populate(hashes);
}

Vec<ZZ_p> Peer::interact_with_client(){
    Recon_manager recon = Recon_manager(cn);
    Pnode* root = tree.get_root();
    bitset newset = bitset(0);
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
                    }
                case recon_state::Bottom:
                    {
                        Message* msg;
                        try{
                            msg = cn.read_message();
                            recon.pop_bottom();
                            recon.handle_reply(msg, bottom.request);
                        } catch(std::exception& e){
                            if((recon.bottom_queue_size()>Recon_settings::max_outstanding_recon_req) || 
                                (recon.request_queue_size()==0)){
                                if (recon.is_flushing())
                                    recon.flush_queue();
                                else{
                                    recon.pop_bottom();
                                    msg = cn.read_message();
                                    recon.handle_reply(msg, bottom.request);
                                }
                            } else {
                                request_entry req = recon.pop_request();
                                recon.send_request(req);
                            }
                        }
                    }
            }
        }
    }
    cn.write_message(new Done{});
    return recon.elements();
}

void Peer::gossip(){
    g_logger.log(Logger_level::DEBUG, "starting gossip client");
    std::srand(time(NULL));
    float jitter = 0.1;
    float r = Utils::get_random(jitter);
    float delay = (1 + (r - jitter/2))*reconciliation_timeout;
    peertype peer = choose_partner();
    g_logger.log(Logger_level::DEBUG, "choosen partner "+ peer.first);
    try{
        start_recon(peer);
    } catch (std::exception e){
        g_logger.log(Logger_level::WARNING, "Cannot connect to partner! " + std::string(e.what()));
    }
}

void Peer::start_recon(peertype peer){
    int http_port = cn.check_remote_config();
    if (http_port > 0){
        peertype peer_http_port;
        peer_http_port.first = peer.first;
        peer_http_port.second = http_port;
        g_logger.log(Logger_level::DEBUG, "Starting recon as client with peer " + peer.first + ", http_port " + std::to_string(http_port));
        client_recon(peer_http_port);
    }
    else
        g_logger.log(Logger_level::WARNING, "mismatched config, canno recon with peer");
}

void Peer::client_recon(peertype peer){
    zset response;
    std::vector<Message*> pending;

    int n=0; 
    Communication comm;
    comm.send=false;
    comm.status=Communication_status::NONE;

    while ((comm.status == Communication_status::NONE) && (n < max_recover_size)){
        // fetch request + craft response
       
        Message* msg = cn.read_message();
        g_logger.log(Logger_level::DEBUG, "prepare to handle message type" + std::to_string(msg->type));
        switch (msg->type){
            case Msg_type::ReconRequestPoly:{
                //ReconRequestPoly
                comm = request_poly_handler((ReconRequestPoly*) msg);
                break;
                   }
            case Msg_type::ReconRequestFull:{
                //Request Full
                comm = request_full_handler((ReconRequestFull*) msg); 
                break;
                   }
            case Msg_type::Elements:{
                //elements
                comm.samples = ((Elements *) msg)->samples;
                break;
                   }
            case Msg_type::Done:{
                //done
                comm.status = Communication_status::DONE;
                return;
                   }
            case Msg_type::Flush:{
                //flush
                comm.send = true;
                break;
                   }
            default:
                //???
                comm.status = Communication_status::ERROR;
        }
        n += comm.samples.size();

        // send response
        pending.insert(pending.end(), comm.messages.begin(), comm.messages.end());
        if (comm.send){
            for (auto m: pending)
                cn.write_message(m);
            pending.empty();
        }
        response.add(comm.samples.elements());
    
    }
    if (comm.status == Communication_status::ERROR){
        ErrorType* error_msg = new ErrorType;
        error_msg->type = Msg_type::ErrorType;
        error_msg->text = "step_error";
        cn.write_message(error_msg);
    } 
    fetch_elements(peer, response.elements());
}

std::pair<Vec<ZZ_p>,Vec<ZZ_p>> Peer::solve(Vec<ZZ_p> r_samples, int r_size, Vec<ZZ_p> l_samples, int l_size, Vec<ZZ_p> points){
    Vec<ZZ_p> values;
    for (int i=0; i<r_samples.length(); i++)
        values.append(r_samples[i]/l_samples[i]);
    int size_diff = r_size-l_size;

    //Interpolation
    //Need to go through
    //all the steps because
    //we need the Lagrange form of
    //the interpolating polynomial
    if (std::abs(size_diff) > values.length()) throw interpolation_exception();
        int mbar = values.length();
    if ((mbar + size_diff)%2 != 0) mbar--;
    int ma = (mbar + size_diff)/2;
    int mb = (mbar - size_diff)/2;
    Mat<ZZ_p> matrix = Mat<ZZ_p>();
    matrix.SetDims(mbar,  mbar+1);
    for (int i=0; i<mbar; i++){
        ZZ_p sum(1);
        ZZ_p ki = points[i];
        ZZ_p fi = values[i];
        for (int j=0; j<ma; j++){
            matrix.put(i, j, sum);
            sum = sum * ki;
        }
        ZZ_p ki_ma = sum;
        negate(sum, fi);
        for (int j=ma; j<mbar; j++){
            matrix.put(i, j, sum);
            sum *= ki;
        }
        ZZ_p fi_ki_mb;
        negate(fi_ki_mb, sum);
        matrix.put(i, mbar, fi_ki_mb - ki_ma);
    }
    //gauss form
    gauss(matrix);

    //normalization
    
    int last;
    ZZ_p scmult,sval,v;
    for (int i=matrix.NumRows()-1; i>=0; i--){
        ZZ_p lead = matrix.get(i,i);
        if (lead != 1){
            for (int j=i; j<matrix.NumCols(); j++){
                ZZ_p v = matrix.get(i,j);
                matrix.put(i,j,v/lead);
        }
        }
    }

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
            matrix.put(j2,j,ZZ_p(0));
        }
    }
    ZZ_pX a_poly;
    ZZ_pX b_poly;
    for (int i=0; i< ma; i++)
        SetCoeff(a_poly, i, matrix.get(i, mbar));
    SetCoeff(a_poly, ma);
    for (int i=0; i<mb; i++)
        SetCoeff(b_poly, i, matrix.get(i+ma, mbar));
    SetCoeff(b_poly, mb);
    ZZ_pX g_poly;
    GCD(g_poly, a_poly, b_poly);
    ZZ_pX num = a_poly/g_poly;
    ZZ_pX den = b_poly/g_poly;
    ZZ_p last_point = points[points.length()-1];
    ZZ_p val = eval(num,last_point);
    ZZ_p last_value = values[values.length()-1];
    if ((val != last_value) ||
            ProbIrredTest(num) ||
            ProbIrredTest(den))
            throw interpolation_exception();
    Vec<ZZ_p> num_factor = FindRoots(num);
    Vec<ZZ_p> den_factor = FindRoots(den);
    return std::make_pair(num_factor, den_factor);
}


Communication Peer::request_poly_handler(ReconRequestPoly* req){
    int r_size = req->size;
    Vec<ZZ_p> points = tree.get_points();
    Vec<ZZ_p> r_samples = req->samples;
    bitset key = req->prefix;
    Pnode* node = tree.node(key);
    Vec<ZZ_p> l_samples = node->get_node_svalues();
    int l_size = node->get_num_elements();
    Vec<ZZ_p> elements;
    std::pair<Vec<ZZ_p>, Vec<ZZ_p>> local_remote;

    try{
        local_remote = solve(r_samples, r_size, l_samples, l_size, points);
    }
    catch (solver_exception& e){
        if (strncmp(e.what(),"low_mbar",8)){
            if ((node->is_leaf()) ||
                    (node->get_num_elements() < ptree_thresh_mult*mbar)){
                elements = node->elements();
                Communication newcomm;
                std::vector<Message*> messages;
                FullElements* full_elements = new FullElements;
                full_elements->type = Msg_type::FullElements;
                zset elements_set(elements);
                full_elements->samples = elements;  
                messages.push_back(full_elements);
                newcomm.messages = messages;
                return newcomm;
        } else {
            throw solver_exception();
        }
        }
        else {
            Communication newcomm;
            SyncFail* fail = new SyncFail;
            fail->type = Msg_type::SyncFail;
            newcomm.messages.push_back(fail);
            return newcomm;
        }
    }
    Communication newcomm;
    zset remote_elements(local_remote.second);
    zset local_elements(local_remote.first);
    newcomm.samples = elements;
    Elements* m_elements = new Elements;
    m_elements->samples = local_elements; 
    m_elements->type = Msg_type::Elements;
    newcomm.messages.push_back(m_elements);
    return newcomm;
}

Communication Peer::request_full_handler(ReconRequestFull* req){
    Myset<ZZ_p> remote_set(req->samples);
    Myset<ZZ_p> local_set;
    Communication newcomm;
    try{
        Pnode* node = tree.node(req->prefix);
        local_set.add(node->elements());
    } catch (std::exception& e){
        newcomm.status = Communication_status::ERROR;
        return newcomm;
    }
    std::pair<Vec<ZZ_p>, Vec<ZZ_p>> local_remote = local_set.symmetric_difference(remote_set); 
    newcomm.samples = local_remote.first;
    Elements* m_elements = new Elements;
    m_elements->samples = local_remote.second;
    m_elements->type = Msg_type::Elements;
    newcomm.messages.push_back(m_elements);
    return newcomm;
}
