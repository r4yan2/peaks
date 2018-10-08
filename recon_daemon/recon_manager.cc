#include "peer.h"

Recon_manager::Recon_manager(Connection_Manager conn_manager){
    cn = conn_manager;
}

Recon_manager::~Recon_manager(){}

void Recon_manager::push_bottom(bottom_entry bottom){
    bottom_queue.push_back(bottom);
}

void Recon_manager::prepend_request(request_entry req){
    if (request_queue.size() < recon_settings.max_request_queue_len){
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
            (remote_set.size() < recon_settings.max_recover_size));
}

bool Recon_manager::bottom_queue_empty(){
    return bottom_queue.empty();
}

void Recon_manager::send_request(request_entry request){
    Message* msg;
    if ((request.node->is_leaf()) || (request.node->get_num_elements() < (int) recon_settings.split_threshold)){
        msg = new ReconRequestFull;
        ((ReconRequestFull*) msg)->prefix = request.key;
        ((ReconRequestFull*) msg)->samples = zset(request.node->elements());
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
    g_logger.log(Logger_level::DEBUG, "handling message type " + std::to_string(msg->type));
    switch (msg->type){
        case (Msg_type::SyncFail):
            {
                if (request.node->is_leaf()){
                    g_logger.log(Logger_level::CRITICAL, "Syncfail at leaf node");
                    delete (SyncFail*) msg;
                    return;
                }
                std::vector<pnode_ptr> children = request.node->children();
                request_entry req;
                req.key = bitset(children[0]->get_node_key());
                g_logger.log(Logger_level::DEBUG, "sending ReconRequestFull for the following node: " + children[0]->get_node_key() + ", which contains " + std::to_string(children[0]->elements().size()) + " elements");
                req.node = children[0];
                push_request(req);
                for (size_t i=1; i<children.size(); i++){
                    request_entry req;
                    req.key = bitset(children[i]->get_node_key());
                    g_logger.log(Logger_level::DEBUG, "sending ReconRequestFull for the following node: " + children[i]->get_node_key() + ", which contains " + std::to_string(children[i]->elements().size()) + " elements");
                    req.node = children[i];
                    prepend_request(req);
                }
                delete (SyncFail*) msg;
                break;
            }
        case (Msg_type::Elements):
            {
                zset samples = ((Elements*)msg)->samples;
                g_logger.log(Logger_level::DEBUG, "handling msg Elements, samples size: " + std::to_string(samples.size()));
                remote_set.add(samples);
                g_logger.log(Logger_level::DEBUG, "Remote set size: " + std::to_string(remote_set.size()));
                delete (Elements*) msg;
                break;
            }
        case (Msg_type::FullElements):
            {
                std::vector<NTL::ZZ_p> elements = request.node->elements();
                zset local_set = zset(elements);
                zset local_needs, remote_needs;
                std::tie(local_needs, remote_needs) = ((FullElements*)msg)->samples.symmetric_difference(local_set);
                Elements* m_elements = new Elements;
                m_elements->samples = remote_needs;
                messages.push_back(m_elements);
                remote_set.add(local_needs);
                delete (FullElements*) msg;
                break;
            }
        default:
            {
                g_logger.log(Logger_level::WARNING, "Arrived unexpected message type " + std::to_string(msg->type));
            }
    }
}

void Recon_manager::flush_queue(){
    messages.push_back(new Flush{});
    cn.send_bulk_messages(messages);
    messages.clear();
    bottom_entry bot;
    bot.state = recon_state::FlushEnded;
    push_bottom(bot);
    toggle_flush(true);
}

std::vector<NTL::ZZ_p> Recon_manager::elements(){
    return remote_set.elements();
}

