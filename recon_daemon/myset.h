#ifndef MYSET_H
#define MYSET_H
#include <NTL/vector.h>
#include <NTL/ZZ_p.h>
#include <NTL/vector.h>

using namespace NTL;
/** My naive implementation of set template class.
 * This template should provide a very basic approach to set container.
 */
template <typename T> class Myset{
    private:
        Vec<T> elems; /**< using an NTL vector underline */
    public:
        Myset<T>(); /**< constructor */
        ~Myset<T>(); /**< destructor */
        Myset<T>(const Vec<T>& vec); /**< constructor from an existing vector */
        Myset<T>& operator=(const Myset<T>& a); /**< copy constructor */
        bool add(const T& elem); /**< add single element to the set */
        void add(const Vec<T>& elem); /**< add an entire NTL Vec to the set */
        std::pair<bool,int> contains(const T& elem); /**< test if the set contains the given element, return <true, position> if found */
        bool del(const T& elem); /**< delete an element from the set */
        T& get(const int i); /**< return the i-th element of the set */
        int size(); /**< actual set size */
        std::pair<Vec<T>,Vec<T>> symmetric_difference(Myset<T>& a); /**< perform a symmetric difference between two sets, return the two vector of differences this-a and a-this */
        Vec<T> elements(); /**< access to the internal NTL Vec */
};
        
#endif
