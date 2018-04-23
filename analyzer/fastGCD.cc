#include "fastGCD.h"
//#include <stdlib.h>
//#include <stdio.h>
//#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <gmpxx.h>
#include <sstream>
#include <utility>
//#include <thread>

#ifdef mpz_raw_64 // if patched gmp, use large format int i/o
#define __mpz_inp_raw mpz_inp_raw_64
#define __mpz_out_raw mpz_out_raw_64
#else // otherwise use normal i/o...beware 2^31 byte size limit
#define __mpz_inp_raw mpz_inp_raw
#define __mpz_out_raw mpz_out_raw
#endif

// return current time as a double, with usec precision
double fastGCD::now() {
    struct timeval t;
    gettimeofday(&t, NULL);
    return (double) t.tv_sec + (double) t.tv_usec / 1000000.;
}

// init vector v to contain count mpzs
void fastGCD::init_vec(vec_t *v, int count) {
    assert(v);
    v->count = count;
    v->el = new mpz_t[count];
    assert(v->el);
    for (int i = 0; i < v->count; i++)
        mpz_init(v->el[i]);
}

// free the vector v
void fastGCD::free_vec(vec_t *v) {
    assert(v);
    for (int i = 0; i < v->count; i++)
        mpz_clear(v->el[i]);
    delete [] v->el;
}

// initializes vec_t *v and fills it with contents of named binary format file
void fastGCD::input_bin_array(vec_t *v, const char *filename) {
    FILE *in = fopen((TMP_FOLDER_GCD + std::string(filename)).c_str(), "rb");
    assert(in);
    int count;
    int ret = fread(&count, sizeof(count), 1, in);
    assert(ret == 1);
    assert(count >= 0);
    init_vec(v, count);
    size_t bytes = 0;
    for (int i = 0; i < count; i++)
        bytes += __mpz_inp_raw(v->el[i], in);
    fclose(in);
}

// initializes vec_t *v and fills it with contents of vector<ZZ>
void fastGCD::input_bin_array(vec_t *v, const std::vector<NTL::ZZ> &values) {
    int count = values.size();
    init_vec(v, count);
    for (int i = 0; i < count; i++) {
        std::stringstream buffer;
        buffer << values[i];
        mpz_set_str(v->el[i], buffer.str().c_str(), 10);
    }
}

// writes vec_t *v to the named file in binary format
void fastGCD::output_bin_array(vec_t *v, const char *filename) {
    FILE *out = fopen((TMP_FOLDER_GCD + std::string(filename)).c_str(), "wb");
    assert(out);
    fwrite(&v->count, sizeof(v->count), 1, out);
    size_t bytes = 0;
    for (int i = 0; i < v->count; i++){
        bytes += __mpz_out_raw(out, v->el[i]);
    }
    fclose(out);
}
// writes vec_t *v to the vuln_moduli vector
void fastGCD::output_hex_array(vec_t *v, std::vector<std::string> &vuln_moduli) {
    for (int i = 0; i < v->count; i++){
        vuln_moduli.emplace_back(mpz_get_str(NULL, 16, v->el[i]));
    }
}

// Executes func(n) over the range [start,end) using NTHREADS
// worker threads.  This is essentially a parallel version of:
//    for (int n=start; n < end; n++) { func(n); }
// You are responsible for ensuring that func() is thread-safe!
void fastGCD::iter_threads(int start, int end, std::function<void(int)> f) {
    int n = start;
    std::mutex mutex;

    std::function<void()> thread_body = [&](){
        for (;;) {
            mutex.lock();
            int i = (n)++;
            mutex.unlock();
            if (i >= end)
                break;
            f(i);
        }
    };

    std::thread thread_id[GCD_THREADS];
    for (auto &i : thread_id) {
        i = std::thread(thread_body);
    }
    for (auto &i : thread_id) {
        i.join();
    }
}

int fastGCD::product_tree() {
    vec_t v;


    input_bin_array(&v, INPUT_FN);

    int level = 0;
    while (v.count > 1) {
        vec_t w;
        init_vec(&w, (v.count + 1) / 2);

        std::function<void(int)> mul_job = [&] (int i) { mpz_mul(w.el[i], v.el[2 * i], v.el[2 * i + 1]); };

        iter_threads(0, v.count / 2, mul_job);

        if (v.count & 1){
            mpz_set(w.el[v.count / 2], v.el[v.count - 1]);
        }

        char name[255];
        snprintf(name, sizeof(name) - 1, "p%d.mpz", level);
        output_bin_array(&w, name);

        free_vec(&v);
        v = w;
        level++;
    }

    free_vec(&v);
    return level;
}

void fastGCD::remainder_tree(int level) {
    char name[255];
    snprintf(name, sizeof(name) - 1, "p%d.mpz", level);
    vec_t P, v;
    input_bin_array(&P, name);

    /* Potential speedup:
    init_vec(&v,2);
    mpz_init(v.el[0],P.el[0]);
    mpz_init(v.el[1],P.el[0]);
    level--;
    P = v;
    */

    while (level > 0) {
        level--;
        snprintf(name, sizeof(name) - 1, "p%d.mpz", level);
        input_bin_array(&v, name);

        std::function<void(int)> mul_job = [&](int i){
            mpz_t s;
            mpz_init(s);
            mpz_mul(s, v.el[i], v.el[i]);
            mpz_mod(v.el[i], P.el[i / 2], s);
            mpz_clear(s);
        };
        iter_threads(0, v.count, mul_job);

        free_vec(&P);
#ifdef OUTPUT_REMAINDER_LEVELS
        snprintf(name, sizeof(name)-1, "r%d.mpz", level);
    output_bin_array(&v, name);
#endif
        P = v;
    }

    // final round
    input_bin_array(&v, INPUT_FN);

    vec_t w;
    init_vec(&w, v.count);

    std::function<void(int)> muldiv_job = [&](int i){
        mpz_t s;
        mpz_init(s);
        mpz_mul(s, v.el[i], v.el[i]);
        mpz_mod(w.el[i], P.el[i / 2], s);
        mpz_divexact(w.el[i], w.el[i], v.el[i]);
        mpz_gcd(w.el[i], w.el[i], v.el[i]);
        mpz_clear(s);
    };
    iter_threads(0, v.count, muldiv_job);

    output_bin_array(&w, OUTPUT_FN.c_str());

    free_vec(&w);
    free_vec(&v);
    free_vec(&P);
}

void fastGCD::emit_results(std::vector<std::string> &vuln_moduli) {
    vec_t moduli;
    input_bin_array(&moduli, INPUT_FN);

    vec_t gcds;
    input_bin_array(&gcds, OUTPUT_FN.c_str());

    // find elements of w that aren't 1
    int size;
    size = 0;
    for (int i = 0; i < gcds.count; i++) {
        if (mpz_cmp_ui(gcds.el[i], 1)) {
            mpz_set(moduli.el[size], moduli.el[i]);
            mpz_set(gcds.el[size], gcds.el[i]);
            size++;
        }
    }
    for (int i = size; i < gcds.count; i++) {
        mpz_clear(moduli.el[i]);
        mpz_clear(gcds.el[i]);
    }
    moduli.count = size;
    gcds.count = size;

    output_hex_array(&moduli, vuln_moduli);

    free_vec(&moduli);
    free_vec(&gcds);
}

std::vector<std::string> fastGCD::compute(){
    std::vector<std::string> broken_values;

    int level = product_tree();
    remainder_tree(level - 1);
    emit_results(broken_values);
    return broken_values;
}

fastGCD::fastGCD(std::vector<NTL::ZZ> INPUT_FN, unsigned int GCD_THREADS) : INPUT_FN(std::move(INPUT_FN)),
                                                                                   GCD_THREADS(GCD_THREADS) {}
