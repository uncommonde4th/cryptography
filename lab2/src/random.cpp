#include "random.hpp"

#include <random>
#include <stdexcept>

#include "number_theory.hpp"

namespace lab2
{
    namespace
    {
        std::random_device& device()
        {
            static thread_local std::random_device instance;
            return instance;
        }
    }

    big_int random_bits(unsigned bits)
    {
        big_int result = 0;
        unsigned produced = 0;

        while (produced < bits)
        {
            result <<= 32;
            result |= big_int(static_cast<std::uint32_t>(device()()));
            produced += 32;
        }

        if (produced > bits)
            result >>= (produced - bits);

        return result;
    }

    big_int random_between(const big_int& min, const big_int& max)
    {
        if (min > max)
            throw std::invalid_argument("random_between: min не может быть больше max");
        if (min == max)
            return min;

        big_int range = max - min;
        unsigned bits = number_theory::bit_length(range);

        big_int value;
        do
        {
            value = random_bits(bits);
        } while (value > range);

        return min + value;
    }
}
