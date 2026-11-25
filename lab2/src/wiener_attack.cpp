#include "wiener_attack.hpp"

#include <cmath>
#include <stdexcept>

#include "number_theory.hpp"
#include "prime_generation.hpp"
#include "random.hpp"

namespace lab2
{
    std::vector<fraction> wiener_attack::continued_fraction_convergents(big_int numerator, big_int denominator)
    {
        if (numerator < 0 || denominator <= 0)
            throw std::invalid_argument("continued_fraction_convergents: ожидаются числитель >= 0 и знаменатель > 0");

        std::vector<fraction> result;

        big_int h_prev2 = 0, h_prev1 = 1;
        big_int k_prev2 = 1, k_prev1 = 0;

        while (denominator != 0)
        {
            big_int a = numerator / denominator;

            big_int h = a * h_prev1 + h_prev2;
            big_int k = a * k_prev1 + k_prev2;
            result.emplace_back(h, k);

            h_prev2 = h_prev1;
            h_prev1 = h;
            k_prev2 = k_prev1;
            k_prev1 = k;

            big_int r = numerator % denominator;
            numerator = denominator;
            denominator = r;
        }
        return result;
    }

    wiener_result wiener_attack::attack(const big_int& n, const big_int& e)
    {
        if (n <= 1 || e <= 1)
            throw std::invalid_argument("wiener_attack::attack: n и e должны быть больше 1");

        wiener_result result;
        result.convergents = continued_fraction_convergents(e, n);

        for (const auto& [k, d] : result.convergents)
        {
            if (k == 0)
                continue;

            big_int value = e * d - 1;
            if (value % k != 0)
                continue;

            big_int phi = value / k;
            if (phi <= 0 || phi >= n)
                continue;

            big_int sum = n - phi + 1;
            big_int discriminant = sum * sum - 4 * n;
            if (discriminant < 0)
                continue;

            big_int root = number_theory::integer_sqrt(discriminant);
            if (root * root != discriminant)
                continue;
            if (((sum + root) & 1) != 0)
                continue;

            big_int p = (sum + root) / 2;
            big_int q = (sum - root) / 2;
            if (p <= 1 || q <= 1 || p * q != n)
                continue;

            result.found = true;
            result.d = d;
            result.phi = phi;
            return result;
        }
        return result;
    }

    weak_key_generator::weak_key_generator(const i_prime_test& test, double min_probability, unsigned bit_length)
        : test_(test), min_probability_(min_probability), bit_length_(bit_length)
    {
        if (std::isnan(min_probability) || min_probability < 0.5 || min_probability >= 1.0)
            throw std::invalid_argument("weak_key_generator: вероятность должна быть в диапазоне [0.5, 1)");
        if (bit_length < 16)
            throw std::invalid_argument("weak_key_generator: битовая длина простых должна быть не меньше 16");
    }

    weak_rsa_key weak_key_generator::generate() const
    {
        while (true)
        {
            auto [p, q] = random_distant_primes(bit_length_, test_, min_probability_);

            big_int n = p * q;
            big_int phi = (p - 1) * (q - 1);

            big_int max_d = number_theory::integer_sqrt(number_theory::integer_sqrt(n)) / 3;
            if (max_d < 3)
                continue;

            big_int d = random_between(3, max_d);
            if (number_theory::gcd(d, phi) != 1)
                continue;
            if (81 * d * d * d * d >= n)
                continue;

            big_int e = number_theory::mod_inverse(d, phi);
            return {n, e, d, phi};
        }
    }
}
