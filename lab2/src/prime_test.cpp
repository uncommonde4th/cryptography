#include "prime_test.hpp"

#include <cmath>
#include <stdexcept>

#include "number_theory.hpp"
#include "random.hpp"

namespace lab2
{
    bool prime_test_base::is_probably_prime(const big_int& n, double min_probability) const
    {
        if (std::isnan(min_probability) || min_probability < 0.5 || min_probability >= 1.0)
            throw std::invalid_argument("is_probably_prime: вероятность должна быть в диапазоне [0.5, 1)");

        if (n < 2)
            return false;
        if (n == 2 || n == 3)
            return true;
        if ((n & 1) == 0)
            return false;

        const unsigned rounds = rounds_count(min_probability);

        for (unsigned i = 0; i < rounds; ++i)
        {
            big_int a = random_between(2, n - 2);

            if (number_theory::gcd(a, n) != 1)
                return false;

            if (!run_iteration(n, a))
                return false;
        }
        return true;
    }

    unsigned prime_test_base::rounds_count(double min_probability) const
    {
        const double bound = iteration_error_bound();
        const double allowed_error = 1.0 - min_probability;

        unsigned rounds = 0;
        double error = 1.0;
        while (error > allowed_error)
        {
            error *= bound;
            ++rounds;
        }
        return rounds;
    }
}
