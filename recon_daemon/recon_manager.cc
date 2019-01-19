#include "peer.h"

Recon_manager::Recon_manager(Connection_Manager &conn_manager, Message_config &msg_config){
    settings = msg_config;
    cn = conn_manager;
}

Recon_manager::~Recon_manager(){}

void Recon_manager::push_bottom(bottom_entry &bottom){
    bottom_queue.push(bottom);
}

void Recon_manager::prepend_request(request_entry &req){
    if (request_queue.size() < settings.max_request_queue_len){
        request_queue.push_front(req);
    }
}

void Recon_manager::push_request(request_entry &request){
    request_queue.push_back(request);
}

bottom_entry Recon_manager::top_bottom(){
    return bottom_queue.front();
}

bottom_entry Recon_manager::pop_bottom(){
    bottom_entry tmp = bottom_queue.front();
    bottom_queue.pop();
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
            (remote_set.size() < settings.max_recover_size));
}

bool Recon_manager::bottom_queue_empty(){
    return bottom_queue.empty();
}

void Recon_manager::send_request(request_entry &request){
    Message* msg;
    if ((request.node->is_leaf()) || (request.node->get_num_elements() < (int) settings.split_threshold)){
        msg = new ReconRequestFull;
        ((ReconRequestFull*) msg)->prefix = request.key;
        ((ReconRequestFull*) msg)->elements = zset(request.node->elements());
    }else{
        msg = new ReconRequestPoly;
        ((ReconRequestPoly*) msg)->prefix = request.key;
        ((ReconRequestPoly*) msg)->size = request.node->get_num_elements();
        ((ReconRequestPoly*) msg)->samples = request.node->get_node_svalues();
    }
    messages.push_back(msg);
    bottom_queue.push(bottom_entry{.request = request});
}

void Recon_manager::handle_reply(Message* msg, request_entry &request){
    switch (msg->type){
        case (Msg_type::SyncFail):
            {
                if (request.node->is_leaf()){
                    syslog(LOG_CRIT, "Syncfail at leaf node");
                    delete (SyncFail*) msg;
                    return;
                }
                std::vector<std::shared_ptr<Pnode>> children = request.node->children();
                request_entry req;
                req.key = bitset(children[0]->get_node_key());
                req.node = children[0];
                push_request(req);
                for (size_t i=1; i<children.size(); i++){
                    request_entry req;
                    req.key = bitset(children[i]->get_node_key());
                    req.node = children[i];
                    prepend_request(req);
                }
                delete (SyncFail*) msg;
                break;
            }
        case (Msg_type::Elements):
            {
                zset elements = ((Elements*)msg)->elements;
                remote_set.add(elements);
                delete (Elements*) msg;
                break;
            }
        case (Msg_type::FullElements):
            {
                std::vector<NTL::ZZ_p> elements = request.node->elements();
                zset local_set = zset(elements);
                zset local_needs, remote_needs;
                std::tie(local_needs, remote_needs) = ((FullElements*)msg)->elements.symmetric_difference(local_set);
                Elements* m_elements = new Elements;
                m_elements->elements = remote_needs;
                messages.push_back(m_elements);
                remote_set.add(local_needs);
                delete (FullElements*) msg;
                break;
            }
        default:
            {
                syslog(LOG_WARNING, "Arrived unexpected message type %d", msg->type);
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

