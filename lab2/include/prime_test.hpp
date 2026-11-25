#pragma once

#include "big_int.hpp"

namespace lab2
{
    class i_prime_test
    {
    public:
        virtual ~i_prime_test() = default;

        virtual bool is_probably_prime(const big_int& n, double min_probability) const = 0;
    };

    class prime_test_base : public i_prime_test
    {
    public:
        bool is_probably_prime(const big_int& n, double min_probability) const final;

    protected:
        virtual bool run_iteration(const big_int& n, const big_int& a) const = 0;

        virtual double iteration_error_bound() const = 0;

        virtual unsigned rounds_count(double min_probability) const;
    };
}
