#ifndef _PEAKS_FILEMANAGER_H
#define _PEAKS_FILEMANAGER_H

#include <string>
#include <map>
#include <memory>
#include "Thread_Pool.h"

using namespace peaks::common;
namespace peaks {
namespace filemanager {

    using handler = unsigned int;
    class Filemanager {
        public:
            static Filemanager& filemanager();
            Filemanager(Filemanager const &) = delete;
            void operator=(Filemanager const &) = delete;
            handler openFile(const std::string &path, bool append=false);
            size_t write(const handler h, const std::string &data);
            void flushFile(const handler h);
            void closeFile(const handler h);
            size_t querySize(const handler);
            std::string queryName(const handler h);
        private:
            std::map<handler, std::shared_ptr<SynchronizedFile>> handler_file_map;
            std::map<std::string, handler> name_handler_map;
            handler next_handler;
            Filemanager();
	        std::mutex m;
    };
}
}

#define FILEMANAGER peaks::filemanager::Filemanager::filemanager()
#endif
