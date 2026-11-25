#include "fermat_test.hpp"

#include "number_theory.hpp"

namespace lab2
{
    bool fermat_test::run_iteration(const big_int& n, const big_int& a) const
    {
        return number_theory::mod_pow(a, n - 1, n) == 1;
    }

    double fermat_test::iteration_error_bound() const
    {
        return 0.5;
    }
}
