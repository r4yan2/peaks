#include "peer.h"

Recon_manager::Recon_manager(Connection_Manager conn_manager){
    cn = conn_manager;
}
Recon_manager::~Recon_manager(){}

void Recon_manager::push_bottom(bottom_entry bottom){
    bottom_queue.push_back(bottom);
}

void Recon_manager::prepend_request(request_entry req){
    if (request_queue.size() < Recon_settings::max_request_queue_len){
        request_queue.push_front(req);
    }
}

void Recon_manager::push_request(request_entry request){
    request_queue.push_back(request);
}

bottom_entry Recon_manager::top_bottom(){
    return bottom_queue.front();
}

bottom_entry Recon_manager::pop_bottom(){
    bottom_entry tmp = bottom_queue.front();
    bottom_queue.pop_front();
    return tmp;
}

request_entry Recon_manager::pop_request(){
    request_entry req = request_queue.front();
    request_queue.pop_front();
    return req;
}

void Recon_manager::toggle_flush(bool new_state){
    flushing = new_state;
}

int Recon_manager::request_queue_size(){
    return request_queue.size();
}

int Recon_manager::bottom_queue_size(){
    return bottom_queue.size();
}

bool Recon_manager::is_flushing(){
    return flushing;
}


bool Recon_manager::done(){
    return ((request_queue.size() == 0) &&
            (bottom_queue.size() == 0) &&
            (remote_set.size() < Recon_settings::max_recover_size));
}

bool Recon_manager::bottom_queue_empty(){
    return bottom_queue.empty();
}

void Recon_manager::send_request(request_entry request){
    Message* msg;
    if ((request.node->is_leaf()) || (request.node->get_num_elements() < Recon_settings::mbar)){
        Vec<ZZ_p> elements = request.node->get_node_elements();
        msg = new ReconRequestFull;
        ((ReconRequestFull*) msg)->prefix = request.key;
        ((ReconRequestFull*) msg)->samples = zset(elements);
    }else{
        msg = new ReconRequestPoly;
        ((ReconRequestPoly*) msg)->prefix = request.key;
        ((ReconRequestPoly*) msg)->size = request.node->get_num_elements();
        ((ReconRequestPoly*) msg)->samples = request.node->get_node_svalues();
    }
    messages.push_back(msg);
    bottom_queue.push_back(bottom_entry{.request = request});
}

void Recon_manager::handle_reply(Message* msg, request_entry request){
    switch (msg->type){
        case (Msg_type::SyncFail):
            {
                if (request.node->is_leaf()){
                    g_logger.log(Logger_level::CRITICAL, "Syncfail at leaf node");
                    return;
                }
                std::vector<Pnode*> children = request.node->children();
                request_entry req;
                req.key = bitset(children[0]->get_node_key());
                req.node = children[0];
                push_request(req);
                for (int i=1; i<children.size(); i++){
                    request_entry req;
                    req.key = bitset(children[i]->get_node_key());
                    req.node = children[i];
                    prepend_request(req);
                }
            }
        case (Msg_type::Elements):
            {
                remote_set.add(((Elements*)msg)->samples);
                break;
            }
        case (Msg_type::FullElements):
            {
                Vec<ZZ_p> elements = request.node->get_node_elements();
                zset local_set = zset(elements);
                zset local_needs, remote_needs;
                std::tie(remote_needs, local_needs) = ((FullElements*)msg)->samples.symmetric_difference(local_set);
                Elements* m_elements = new Elements;
                m_elements->samples = remote_needs;
                messages.push_back(m_elements);
                remote_set.add(local_needs);
            }
    }
}

void Recon_manager::flush_queue(){
    messages.push_back(new Flush{});
    for (auto msg: messages)
        cn.write_message(msg);
    messages.clear();
    bottom_entry bot;
    bot.state = recon_state::FlushEnded;
    push_bottom(bot);
    toggle_flush(true);
}

Vec<ZZ_p> Recon_manager::elements(){
    return remote_set.elements();
}

