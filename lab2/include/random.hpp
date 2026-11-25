#pragma once

#include "big_int.hpp"

namespace lab2
{
    big_int random_bits(unsigned bits);

    big_int random_between(const big_int& min, const big_int& max);
}
