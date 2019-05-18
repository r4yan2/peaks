set(SOURCE_FILES recon_daemon.cc peer.cc recon_manager.cc Connection_Manager.cc Message.cc Buffer.cc Bitset.cc exception.cc myset.cc pTreeDB.cc DBManager.cc Utils.cc DBStruct.h)

add_library(recon_daemon ${SOURCE_FILES})
