#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "big_int.hpp"

namespace lab2
{
    struct ext_gcd_result
    {
        big_int gcd;
        big_int x;
        big_int y;
    };

    class number_theory final
    {
    public:
        number_theory() = delete;

        static int legendre_symbol(const big_int& a, const big_int& p);
        static int jacobi_symbol(const big_int& a, const big_int& n);

        static big_int gcd(const big_int& a, const big_int& b);
        static ext_gcd_result extended_gcd(const big_int& a, const big_int& b);
        static big_int binary_gcd(const big_int& a, const big_int& b);

        static big_int mod_pow(const big_int& value, const big_int& exponent, const big_int& modulus);

        static big_int euler_by_definition(const big_int& n);
        static big_int euler_by_factorization(const big_int& n);
        static big_int euler_by_fourier(const big_int& n);

        static big_int carmichael(const big_int& n);

        static big_int mod_inverse(const big_int& a, const big_int& modulus);
        static big_int integer_sqrt(const big_int& n);
        static unsigned bit_length(big_int n);

        static std::vector<std::pair<big_int, unsigned>> factorize(big_int n);
    };
}
