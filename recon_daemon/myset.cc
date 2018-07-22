#include "myset.h"

template<typename T> Myset<T>::Myset(){
}

template<typename T> Myset<T>::~Myset(){
}

template<typename T> Myset<T>::Myset(const Vec<T>& vec){
    for (auto elem: vec) add(elem);
}

template<typename T> Myset<T>::Myset(const Myset& a){
    for (auto elem : a.elements())
        elems.append(elem);
}

template<typename T> bool Myset<T>::add(const T& elem){
    for (int i=0; i<elems.length(); i++)
        if (elem == elems[i]) return false;
    elems.append(elem);
    return false;
}

template<typename T> void Myset<T>::add(const Vec<T>& elem){
    for (auto e: elem) add(e);
}

template<typename T> void Myset<T>::add(const Myset<T>& a){
    elems.append(a.elements());
}

template<typename T> std::pair<bool,int> Myset<T>::contains(const T& elem){
    for (int i=0; i<elems.length(); i++)
        if (elem == elems[i]) return std::make_pair(true,i);
    return std::make_pair(false, -1);
}


template<typename T> bool Myset<T>::del(const T& elem){
    std::pair<bool,int> res = contains(elem);
    if (res.first){
        Vec<T> new_elems;
        for (int i=0; i<elems.length(); i++)
            if (i!=res.second) new_elems.append(elems[i]);
        elems = new_elems;
    }
    return res.first;
}

template<typename T> T& Myset<T>::get(const int i){
    return elems[i];
}

template<typename T> int Myset<T>::size(){
    return elems.length();
}

template<typename T> Vec<T> Myset<T>::elements() const{
    return elems;
}

template<typename T> std::pair<Vec<T>, Vec<T>> Myset<T>::symmetric_difference(Myset<T>& a){
    Vec<T> c, e;
    Myset<T> d;
    for (int i=0; i<a.size();i++){
        auto elem = a.get(i);
        if (contains(elem).first) d.add(elem);
        else c.append(elem);
    }
    for (int i=0; i<elems.length(); i++){
        auto elem = elems[i];
        if (!(d.contains(elem).first)) e.append(elem);
    }
    return std::make_pair(e,c);
}

template class Myset<ZZ_p>;
