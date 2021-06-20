#include "config.h"

using namespace peaks;

Context& Context::context(){
    static Context instance;
    return instance;
}
