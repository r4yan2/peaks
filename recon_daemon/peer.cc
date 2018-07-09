#include "peer.h"

using namespace NTL;

Peer::Peer(peertype peer){
    syslog(LOG_INFO, "Initiating recon with %s", peer.first.c_str());
    Connection_Manager cn;
    cn.init(peer);
}

peertype Peer::choose_partner(){
    std::vector<peertype> membership;
    std::ifstream f("membership");
    std::string addr;
    int port;
    while(f >> addr >> port){
        std::cout << addr << port << "\n";
        membership.push_back(std::make_pair(addr, port));
    }
    int choice = Utils::get_random(membership.size());
    return membership[choice];
}

void Peer::gossip(){
    std::srand(time(NULL));
    float jitter = 0.1;
    float r = Utils::get_random(jitter);
    float delay = (1 + (r - jitter/2))*reconciliation_timeout;
    peertype peer = choose_partner();
    try{
        start_recon();
    } catch (std::exception e){
        syslog(LOG_INFO, "Cannot connect to partner! %s", e.what());
    }
}

void Peer::start_recon(){
    Peer_config peer_config = {"1.0.0", 11371, PTree_settings::bq, PTree_settings::mbar, "ciao, mamma"};
    Peer_config remote_config;
    remote_config = cn.get_remote_config(peer_config);
    client_recon(remote_config, cn);
}

void Peer::client_recon(Peer_config remote_config, Connection_Manager cn){
    zset response;
    std::vector<Message> pending;

    int n=0; 
    Communication comm;
    comm.send=false;
    comm.status=Communication_status::NONE;

    while ((comm.status == Communication_status::NONE) && (n < max_recover_size)){
        // fetch request + craft response
       
        Message msg = cn.read_message();
        switch (msg.type){
            case Msg_type::ReconRequestPoly:{
                //ReconRequestPoly
                ReconRequestPoly* req = ((ReconRequestPoly *) msg.data);
                comm = request_poly_handler(req);
                break;
                   }
            case Msg_type::ReconRequestFull:{
                //Request Full
                ReconRequestFull* req = ((ReconRequestFull *) msg.data);
                comm = request_full_handler(req); 
                break;
                   }
            case Msg_type::Elements:{
                //elements
                comm.samples = ((Elements *) msg.data)->samples;
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
        Message error_msg;
        error_msg.type = Msg_type::ErrorType;
        ((ErrorType *) error_msg.data)->text = "step_error";
        cn.write_message(error_msg);
    } 
    else
        cn.send_items(response);
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
    std::cout << (a_poly/b_poly) << "\t" << interpolate(points, values) << "\n";
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
                std::vector<Message> messages;
                Message full_elements;
                full_elements.type = Msg_type::FullElements;
                full_elements.data = new FullElements;
                zset elements_set(elements);
                ((FullElements *) full_elements.data)->samples = elements;  
                messages.push_back(full_elements);
                newcomm.messages = messages;
                return newcomm;
        } else {
            throw solver_exception();
        }
        }
        else {
            Communication newcomm;
            Message fail;
            fail.type = Msg_type::SyncFail;
            fail.data = new SyncFail;
            newcomm.messages.push_back(fail);
            return newcomm;
        }
    }
    Communication newcomm;
    zset remote_elements(local_remote.second);
    zset local_elements(local_remote.first);
    newcomm.samples = elements;
    Message m_elements;
    m_elements.type = Msg_type::Elements;
    m_elements.data = new Elements;
    ((Elements *) m_elements.data)->samples = local_elements; 
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
    Message m_elements;
    m_elements.type = Msg_type::Elements;
    m_elements.data = new Elements;
    ((Elements *) m_elements.data)->samples = local_remote.second;
    newcomm.messages.push_back(m_elements);
}
