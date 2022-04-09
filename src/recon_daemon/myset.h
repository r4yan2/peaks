#ifndef MYSET_H
#define MYSET_H
#include <NTL/ZZ_p.h>
#include <vector>

namespace peaks{
namespace recon{
/** My naive implementation of set template class.
 * This template should provide a very basic approach to set container.
 */
template <typename T> class Myset{
    private:
        std::vector<T> elems; /**< using an NTL vector underline */
    public:
        Myset<T>(); /**< constructor */
        ~Myset<T>(); /**< destructor */
        Myset<T>(const std::vector<T>& vec); /**< constructor from an existing vector */
        Myset<T>(const Myset<T>& a); /**< copy constructor */
        bool add(const T& elem); /**< add single element to the set */
        void add(const std::vector<T>& elem); /**< add an entire NTL std::vector to the set */
        void add(const Myset<T>& a); /**< add an entire NTL std::vector to the set */
        std::pair<bool,int> contains(const T& elem); /**< test if the set contains the given element, return <true, position> if found */
        bool del(const T& elem); /**< delete an element from the set */
        T& get(const int i); /**< return the i-th element of the set */
        int size(); /**< actual set size */
        typename std::vector<T>::iterator begin(); /**< actual set size */
        typename std::vector<T>::iterator end(); /**< actual set size */
        std::pair<std::vector<T>,std::vector<T>> symmetric_difference(Myset<T>& a); /**< perform a symmetric difference between two sets, return the two vector of differences this-a and a-this */
        std::vector<T> elements() const; /**< access to the internal NTL std::vector */
};

typedef Myset<NTL::ZZ_p> zpset;
typedef Myset<NTL::ZZ> zset;

        
}
}
#endif
