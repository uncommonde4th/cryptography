#pragma once

#include "prime_test.hpp"

namespace lab2
{
    class miller_rabin_test final : public prime_test_base
    {
    protected:
        bool run_iteration(const big_int& n, const big_int& a) const override;
        double iteration_error_bound() const override;
    };
}
