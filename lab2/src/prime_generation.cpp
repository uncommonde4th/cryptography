#include "prime_generation.hpp"

#include <stdexcept>

#include "random.hpp"

namespace lab2
{
    big_int random_prime(unsigned bit_length, const i_prime_test& test, double min_probability)
    {
        if (bit_length < 3)
            throw std::invalid_argument("random_prime: битовая длина должна быть не меньше 3");

        while (true)
        {
            big_int candidate = random_bits(bit_length);
            candidate |= (big_int(1) << (bit_length - 1));
            candidate |= 1;

            if (test.is_probably_prime(candidate, min_probability))
                return candidate;
        }
    }

    std::pair<big_int, big_int> random_distant_primes(unsigned bit_length, const i_prime_test& test,
                                                      double min_probability)
    {
        const big_int min_difference = big_int(1) << (bit_length - 3);

        while (true)
        {
            big_int p = random_prime(bit_length, test, min_probability);
            big_int q = random_prime(bit_length, test, min_probability);

            big_int difference = p > q ? big_int(p - q) : big_int(q - p);
            if (difference <= min_difference)
                continue;

            return {p, q};
        }
    }
}
