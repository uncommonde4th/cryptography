#include "number_theory.hpp"

#include <cmath>
#include <limits>
#include <stdexcept>

namespace lab2
{
    namespace
    {
        big_int absolute(const big_int& x)
        {
            return x < 0 ? big_int(-x) : x;
        }

        bool is_even(const big_int& x)
        {
            return (x & 1) == 0;
        }

        std::uint64_t gcd_u64(std::uint64_t a, std::uint64_t b)
        {
            while (b != 0)
            {
                std::uint64_t r = a % b;
                a = b;
                b = r;
            }
            return a;
        }

        big_int lcm(const big_int& a, const big_int& b)
        {
            return a / number_theory::gcd(a, b) * b;
        }
    }

    int number_theory::legendre_symbol(const big_int& a, const big_int& p)
    {
        if (p < 3 || is_even(p))
            throw std::invalid_argument("legendre_symbol: p должно быть нечётным простым числом");

        big_int r = mod_pow(a, (p - 1) / 2, p);

        if (r == 0)
            return 0;
        if (r == 1)
            return 1;
        if (r == p - 1)
            return -1;

        throw std::invalid_argument("legendre_symbol: p не является простым");
    }

    int number_theory::jacobi_symbol(const big_int& a_in, const big_int& n_in)
    {
        if (n_in <= 0 || is_even(n_in))
            throw std::invalid_argument("jacobi_symbol: n должно быть положительным нечётным");

        big_int a = a_in % n_in;
        if (a < 0)
            a += n_in;
        big_int n = n_in;
        int sign = 1;

        while (a != 0)
        {
            while (is_even(a))
            {
                a >>= 1;
                big_int r = n % 8;
                if (r == 3 || r == 5)
                    sign = -sign;
            }

            if (a % 4 == 3 && n % 4 == 3)
                sign = -sign;

            std::swap(a, n);
            a %= n;
        }

        return n == 1 ? sign : 0;
    }

    big_int number_theory::gcd(const big_int& a_in, const big_int& b_in)
    {
        big_int a = absolute(a_in);
        big_int b = absolute(b_in);

        while (b != 0)
        {
            big_int r = a % b;
            a = b;
            b = r;
        }
        return a;
    }

    ext_gcd_result number_theory::extended_gcd(const big_int& a, const big_int& b)
    {
        big_int old_r = a, r = b;
        big_int old_x = 1, x = 0;
        big_int old_y = 0, y = 1;

        while (r != 0)
        {
            big_int q = old_r / r;

            big_int next_r = old_r - q * r;
            old_r = r;
            r = next_r;

            big_int next_x = old_x - q * x;
            old_x = x;
            x = next_x;

            big_int next_y = old_y - q * y;
            old_y = y;
            y = next_y;
        }

        if (old_r < 0)
        {
            old_r = -old_r;
            old_x = -old_x;
            old_y = -old_y;
        }
        return {old_r, old_x, old_y};
    }

    big_int number_theory::binary_gcd(const big_int& a_in, const big_int& b_in)
    {
        big_int a = absolute(a_in);
        big_int b = absolute(b_in);

        if (a == 0)
            return b;
        if (b == 0)
            return a;

        unsigned shift = 0;
        while (is_even(a) && is_even(b))
        {
            a >>= 1;
            b >>= 1;
            ++shift;
        }

        while (is_even(a))
            a >>= 1;

        while (b != 0)
        {
            while (is_even(b))
                b >>= 1;
            if (a > b)
                std::swap(a, b);
            b -= a;
        }

        return a << shift;
    }

    big_int number_theory::mod_pow(const big_int& value, const big_int& exponent_in, const big_int& modulus)
    {
        if (exponent_in < 0)
            throw std::invalid_argument("mod_pow: показатель степени не может быть отрицательным");
        if (modulus <= 0)
            throw std::invalid_argument("mod_pow: модуль должен быть положительным");

        big_int base = value % modulus;
        if (base < 0)
            base += modulus;

        big_int exponent = exponent_in;
        big_int result = 1 % modulus;

        while (exponent > 0)
        {
            if (!is_even(exponent))
                result = result * base % modulus;
            base = base * base % modulus;
            exponent >>= 1;
        }
        return result;
    }

    big_int number_theory::euler_by_definition(const big_int& n)
    {
        if (n <= 0)
            throw std::invalid_argument("euler_by_definition: n должно быть положительным");

        big_int count = 0;
        for (big_int k = 1; k <= n; ++k)
            count += (gcd(k, n) == 1) ? 1 : 0;

        return count;
    }

    big_int number_theory::euler_by_factorization(const big_int& n)
    {
        if (n <= 0)
            throw std::invalid_argument("euler_by_factorization: n должно быть положительным");

        big_int result = 1;
        for (const auto& [p, k] : factorize(n))
        {
            big_int term = p - 1;
            for (unsigned i = 1; i < k; ++i)
                term *= p;
            result *= term;
        }
        return result;
    }

    big_int number_theory::euler_by_fourier(const big_int& n)
    {
        if (n <= 0)
            throw std::invalid_argument("euler_by_fourier: n должно быть положительным");
        if (n > std::numeric_limits<std::uint64_t>::max())
            throw std::invalid_argument("euler_by_fourier: n слишком велико для метода (цикл по k до n)");

        const std::uint64_t m = n.convert_to<std::uint64_t>();
        const long double two_pi = 2.0L * std::acos(-1.0L);

        long double sum = 0.0L;
        for (std::uint64_t k = 1; k <= m; ++k)
        {
            long double angle = two_pi * static_cast<long double>(k) / static_cast<long double>(m);
            sum += static_cast<long double>(gcd_u64(k, m)) * std::cos(angle);
        }

        return big_int(static_cast<long long>(std::llround(sum)));
    }

    big_int number_theory::carmichael(const big_int& n)
    {
        if (n <= 0)
            throw std::invalid_argument("carmichael: n должно быть положительным");

        big_int result = 1;
        for (const auto& [p, k] : factorize(n))
        {
            big_int component = p - 1;
            for (unsigned i = 1; i < k; ++i)
                component *= p;

            if (p == 2 && k >= 3)
                component >>= 1;

            result = lcm(result, component);
        }
        return result;
    }

    big_int number_theory::mod_inverse(const big_int& a, const big_int& modulus)
    {
        if (modulus <= 1)
            throw std::invalid_argument("mod_inverse: модуль должен быть больше единицы");

        big_int reduced = a % modulus;
        if (reduced < 0)
            reduced += modulus;

        ext_gcd_result r = extended_gcd(reduced, modulus);
        if (r.gcd != 1)
            throw std::invalid_argument("mod_inverse: числа не взаимно просты");

        big_int inv = r.x % modulus;
        if (inv < 0)
            inv += modulus;
        return inv;
    }

    unsigned number_theory::bit_length(big_int n)
    {
        unsigned bits = 0;
        while (n > 0)
        {
            n >>= 1;
            ++bits;
        }
        return bits;
    }

    big_int number_theory::integer_sqrt(const big_int& n)
    {
        if (n < 0)
            throw std::invalid_argument("integer_sqrt: число не может быть отрицательным");
        if (n < 2)
            return n;

        big_int x = big_int(1) << ((bit_length(n) + 1) / 2);
        while (true)
        {
            big_int y = (x + n / x) >> 1;
            if (y >= x)
                return x;
            x = y;
        }
    }

    std::vector<std::pair<big_int, unsigned>> number_theory::factorize(big_int n)
    {
        if (n <= 0)
            throw std::invalid_argument("factorize: n должно быть положительным");

        std::vector<std::pair<big_int, unsigned>> result;

        for (big_int d = 2; d * d <= n; d += (d == 2 ? 1 : 2))
        {
            if (n % d != 0)
                continue;

            unsigned power = 0;
            while (n % d == 0)
            {
                n /= d;
                ++power;
            }
            result.emplace_back(d, power);
        }

        if (n > 1)
            result.emplace_back(n, 1u);

        return result;
    }
}
