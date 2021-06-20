#ifndef ANALYZER_FASTGCD_H
#define ANALYZER_FASTGCD_H

#include <NTL/ZZ.h>
#include <vector>
#include <gmp.h>
#include <mutex>
#include <functional>
#include <thread>

namespace peaks{
namespace analyzer{
class fastGCD{
public:
    fastGCD(std::vector<NTL::ZZ> INPUT_FN, unsigned int GCD_THREADS, std::string &analyzer_gcd_folder);

    std::vector<std::string> compute();

private:
    std::string gcd_folder;

    const std::vector<NTL::ZZ> INPUT_FN;
    const std::string OUTPUT_FN = "output.mpz";
    const unsigned int GCD_THREADS = std::thread::hardware_concurrency() / 2;

    typedef struct vec_ {
        mpz_t *el;
        int count;
    } vec_t;

    double now();

    //int file_exists(char *filename);

    //void prep_hex_input(char *infile, char *outfile);

    void init_vec(vec_ *v, int count);

    void free_vec(vec_ *v);

    void input_bin_array(vec_ *v, const char *filename);

    void output_bin_array(vec_ *v, const char *filename);

    //void output_hex_array(vec_ *v, const char *filename);

    void output_hex_array(vec_ *v, std::vector<std::string> &vuln_moduli);

    //void uniq(vec_ *v);

    void iter_threads(int start, int end, std::function<void(int)> f);

    int product_tree();

    void remainder_tree(int level);

    void emit_results(std::vector<std::string> &vuln_moduli);

    void input_bin_array(vec_ *v, const std::vector<NTL::ZZ> &values);

};

}
}
#endif //ANALYZER_FASTGCD_H
