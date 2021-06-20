#ifndef PEAKS_DB_KEY_H_
#define PEAKS_DB_KEY_H_

namespace peaks {
namespace pks{

class DB_Key {
    public:
       DB_Key(int b, char a, const std::string& i, const std::string& d, const std::string& u)
       : bits(b)
       , algo(a)
       , keyID(i)
       , date(d)
       , userID(u)
       { }
       virtual ~DB_Key() { }
       int bits;
       char algo;
       std::string keyID;
       std::string date;
       std::string userID;
};

}
}
#endif // PEAKS_DB_KEY_H_
