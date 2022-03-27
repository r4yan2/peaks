#include "FileManager.h"
#include "utils.h"
#define MAX_HANDLER 100000

using namespace peaks::common;
namespace peaks{
namespace filemanager{
    Filemanager::Filemanager(){
        next_handler = 0;
    }
    
    Filemanager& Filemanager::filemanager(){
        static Filemanager manager;
        return manager;
    }
    
    handler Filemanager::openFile(const std::string &path, bool append){
        std::lock_guard <std::mutex> lock(m);
        auto it = name_handler_map.find(path);
        if (it != name_handler_map.end())
            return it->second; //handler found!
        auto ptr = std::make_shared<SynchronizedFile>(path, append);
        handler new_handler;
        do {
            new_handler = next_handler;
            next_handler = (next_handler + 1) % MAX_HANDLER;
        } while (handler_file_map.find(new_handler) != handler_file_map.end());
        handler_file_map[new_handler] = ptr;
        name_handler_map[path] = new_handler;
        return new_handler;
    }

    size_t Filemanager::write(const handler h, const std::string &data){
        std::lock_guard <std::mutex> lock(m);
        return handler_file_map[h]->write(data);
    }

    void Filemanager::flushFile(const handler h){
        std::lock_guard <std::mutex> lock(m);
        handler_file_map[h]->flush();
    }

    void Filemanager::closeFile(const handler h){
        std::lock_guard <std::mutex> lock(m);
        auto it = handler_file_map.find(h);
        if (it == handler_file_map.end())
            return; // already closed
        auto name = handler_file_map[h]->get_name();
        handler_file_map[h]->close();
        handler_file_map.erase(h);
        name_handler_map.erase(name);
    }

    size_t Filemanager::querySize(const handler h){
        std::lock_guard <std::mutex> lock(m);
        return handler_file_map[h]->size();
    }

    std::string Filemanager::queryName(const handler h){
        std::lock_guard <std::mutex> lock(m);
        return handler_file_map[h]->get_name();
    }
}}
