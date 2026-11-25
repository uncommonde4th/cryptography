#include "rsa.hpp"

#include <cmath>
#include <stdexcept>

#include "fermat_test.hpp"
#include "miller_rabin_test.hpp"
#include "number_theory.hpp"
#include "prime_generation.hpp"
#include "random.hpp"
#include "solovay_strassen_test.hpp"

namespace lab2
{
    rsa::key_generator::key_generator(test_type type, double min_probability, unsigned bit_length)
        : min_probability_(min_probability), bit_length_(bit_length)
    {
        if (std::isnan(min_probability) || min_probability < 0.5 || min_probability >= 1.0)
            throw std::invalid_argument("rsa: вероятность простоты должна быть в диапазоне [0.5, 1)");
        if (bit_length < 8)
            throw std::invalid_argument("rsa: битовая длина простых должна быть не меньше 8");

        switch (type)
        {
        case test_type::fermat:
            test_ = std::make_unique<fermat_test>();
            break;
        case test_type::solovay_strassen:
            test_ = std::make_unique<solovay_strassen_test>();
            break;
        case test_type::miller_rabin:
            test_ = std::make_unique<miller_rabin_test>();
            break;
        default:
            throw std::invalid_argument("rsa: неизвестный тест простоты");
        }
    }

    rsa::key_generator::key_pair rsa::key_generator::generate() const
    {
        while (true)
        {
            auto [p, q] = random_distant_primes(bit_length_, *test_, min_probability_);

            big_int n = p * q;
            big_int phi = (p - 1) * (q - 1);

            big_int e = 65537;
            if (e >= phi)
                e = random_between(3, phi - 1);

            if (number_theory::gcd(e, phi) != 1)
                continue;

            big_int d = number_theory::mod_inverse(e, phi);

            if (d * d <= n)
                continue;

            return {n, e, d};
        }
    }

    rsa::rsa(test_type type, double min_probability, unsigned bit_length)
        : generator_(type, min_probability, bit_length)
    {
    }

    void rsa::generate_keys()
    {
        auto keys = generator_.generate();
        n_ = keys.n;
        e_ = keys.e;
        d_ = keys.d;
        has_key_ = true;
    }

    void rsa::require_key() const
    {
        if (!has_key_)
            throw std::logic_error("rsa: ключи не сгенерированы (вызовите generate_keys)");
    }

    rsa::public_key rsa::get_public_key() const
    {
        require_key();
        return {n_, e_};
    }

    big_int rsa::encrypt(const big_int& message) const
    {
        require_key();
        if (message < 0 || message >= n_)
            throw std::out_of_range("rsa::encrypt: сообщение должно лежать в диапазоне [0, n)");
        return number_theory::mod_pow(message, e_, n_);
    }

    big_int rsa::decrypt(const big_int& cipher) const
    {
        require_key();
        if (cipher < 0 || cipher >= n_)
            throw std::out_of_range("rsa::decrypt: шифротекст должен лежать в диапазоне [0, n)");
        return number_theory::mod_pow(cipher, d_, n_);
    }
}
