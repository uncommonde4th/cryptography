#pragma once

#include <utility>

#include "big_int.hpp"
#include "prime_test.hpp"

namespace lab2
{
    big_int random_prime(unsigned bit_length, const i_prime_test& test, double min_probability);

    std::pair<big_int, big_int> random_distant_primes(unsigned bit_length, const i_prime_test& test,
                                                      double min_probability);
}
