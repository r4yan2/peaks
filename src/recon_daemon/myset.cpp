#include "myset.h"

namespace peaks{
namespace recon{

template<typename T> Myset<T>::Myset(){
}

template<typename T> Myset<T>::~Myset(){
}

template<typename T> Myset<T>::Myset(const std::vector<T>& vec){
    for (auto elem: vec) add(elem);
}

template<typename T> Myset<T>::Myset(const Myset& a){
    for (auto elem : a.elements())
        elems.push_back(elem);
}

template<typename T> bool Myset<T>::add(const T& elem){
    for (size_t i=0; i<elems.size(); i++)
        if (elem == elems[i]) return false;
    elems.push_back(elem);
    return true;
}

template<typename T> void Myset<T>::add(const std::vector<T>& elem){
    for (auto e: elem) add(e);
}

template<typename T> void Myset<T>::add(const Myset<T>& a){
    std::vector<T> v = a.elements();
    elems.insert(elems.end(), v.begin(), v.end());
}

template<typename T> std::pair<bool,int> Myset<T>::contains(const T& elem){
    for (size_t i=0; i<elems.size(); i++)
        if (elem == elems[i]) return std::make_pair(true,i);
    return std::make_pair(false, -1);
}


template<typename T> bool Myset<T>::del(const T& elem){
    std::pair<bool,int> res = contains(elem);
    if (res.first){
        std::vector<T> new_elems;
        for (int i=0; i<size(); i++)
            if (i != res.second) new_elems.push_back(elems[i]);
        elems = new_elems;
    }
    return res.first;
}

template<typename T> T& Myset<T>::get(const int i){
    return elems[i];
}

template<typename T> int Myset<T>::size(){
    return elems.size();
}

template<typename T> std::vector<T> Myset<T>::elements() const{
    return elems;
}

template<typename T> std::pair<std::vector<T>, std::vector<T>> Myset<T>::symmetric_difference(Myset<T>& a){
    std::vector<T> c, e;
    Myset<T> d;
    for (int i=0; i<a.size();i++){
        auto elem = a.get(i);
        if (contains(elem).first) d.add(elem);
        else c.push_back(elem);
    }
    for (int i=0; i<size(); i++){
        auto elem = elems[i];
        if (!(d.contains(elem).first)) e.push_back(elem);
    }
    return std::make_pair(e,c);
}

template class Myset<NTL::ZZ_p>;
}
}
