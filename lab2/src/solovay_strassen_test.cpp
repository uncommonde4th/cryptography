#include "solovay_strassen_test.hpp"

#include "number_theory.hpp"

namespace lab2
{
    bool solovay_strassen_test::run_iteration(const big_int& n, const big_int& a) const
    {
        const int symbol = number_theory::jacobi_symbol(a, n);
        if (symbol == 0)
            return false;

        big_int expected = symbol;
        if (expected < 0)
            expected += n;

        return number_theory::mod_pow(a, (n - 1) / 2, n) == expected;
    }

    double solovay_strassen_test::iteration_error_bound() const
    {
        return 0.5;
    }
}
