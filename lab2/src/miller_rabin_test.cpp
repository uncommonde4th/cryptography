#include "miller_rabin_test.hpp"

#include "number_theory.hpp"

namespace lab2
{
    bool miller_rabin_test::run_iteration(const big_int& n, const big_int& a) const
    {
        big_int d = n - 1;
        unsigned s = 0;
        while ((d & 1) == 0)
        {
            d >>= 1;
            ++s;
        }

        big_int x = number_theory::mod_pow(a, d, n);
        if (x == 1 || x == n - 1)
            return true;

        for (unsigned i = 1; i < s; ++i)
        {
            x = x * x % n;
            if (x == n - 1)
                return true;
        }
        return false;
    }

    double miller_rabin_test::iteration_error_bound() const
    {
        return 0.25;
    }
}
