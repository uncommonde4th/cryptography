#pragma once

#include <utility>
#include <vector>

#include "big_int.hpp"
#include "prime_test.hpp"

namespace lab2
{
    using fraction = std::pair<big_int, big_int>;

    struct wiener_result
    {
        bool found = false;
        big_int d;
        big_int phi;
        std::vector<fraction> convergents;
    };

    class wiener_attack final
    {
    public:
        wiener_attack() = delete;

        static std::vector<fraction> continued_fraction_convergents(big_int numerator, big_int denominator);

        static wiener_result attack(const big_int& n, const big_int& e);
    };

    struct weak_rsa_key
    {
        big_int n;
        big_int e;
        big_int d;
        big_int phi;
    };

    class weak_key_generator final
    {
    public:
        weak_key_generator(const i_prime_test& test, double min_probability, unsigned bit_length);

        weak_rsa_key generate() const;

    private:
        const i_prime_test& test_;
        double min_probability_;
        unsigned bit_length_;
    };
}
