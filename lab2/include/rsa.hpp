#pragma once

#include <memory>

#include "big_int.hpp"
#include "prime_test.hpp"

namespace lab2
{
    class rsa final
    {
    public:
        enum class test_type
        {
            fermat,
            solovay_strassen,
            miller_rabin
        };

        struct public_key
        {
            big_int n;
            big_int e;
        };

        rsa(test_type type, double min_probability, unsigned bit_length);

        void generate_keys();

        public_key get_public_key() const;

        big_int encrypt(const big_int& message) const;
        big_int decrypt(const big_int& cipher) const;

    private:
        class key_generator
        {
        public:
            struct key_pair
            {
                big_int n;
                big_int e;
                big_int d;
            };

            key_generator(test_type type, double min_probability, unsigned bit_length);

            key_pair generate() const;

        private:
            std::unique_ptr<i_prime_test> test_;
            double min_probability_;
            unsigned bit_length_;
        };

        void require_key() const;

        key_generator generator_;
        big_int n_;
        big_int e_;
        big_int d_;
        bool has_key_ = false;
    };
}
