#include "tests.hpp"

#include <iostream>
#include <string>
#include <vector>

#include "fermat_test.hpp"
#include "miller_rabin_test.hpp"
#include "number_theory.hpp"
#include "random.hpp"
#include "rsa.hpp"
#include "solovay_strassen_test.hpp"
#include "wiener_attack.hpp"

namespace lab2::tests
{
    namespace
    {
        int failures = 0;

        template <typename T, typename U>
        void check(const std::string& label, const T& actual, const U& expected)
        {
            const bool ok = (actual == expected);
            if (!ok)
                ++failures;
            std::cout << "  " << label << " = " << actual << "; ожидается " << expected
                      << (ok ? "  [ok]" : "  [FAIL]") << '\n';
        }

        void check_true(const std::string& label, bool condition)
        {
            if (!condition)
                ++failures;
            std::cout << "  " << label << (condition ? "  [ok]" : "  [FAIL]") << '\n';
        }

        void header(const std::string& title)
        {
            std::cout << "\n==================== " << title << " ====================\n";
        }

    }

    int failed_checks()
    {
        return failures;
    }

    void run_task1()
    {
        header("Пункт 1: сервис теории чисел");

        std::cout << "\n< Алгоритмы Евклида >\n";
        check("gcd(48, 18)", number_theory::gcd(48, 18), 6);
        check("binary_gcd(48, 18)", number_theory::binary_gcd(48, 18), 6);
        check("gcd(-48, 18)", number_theory::gcd(-48, 18), 6);

        auto bezout = number_theory::extended_gcd(48, 18);
        std::cout << "  extended_gcd(48, 18): gcd = " << bezout.gcd << ", x = " << bezout.x
                  << ", y = " << bezout.y << '\n';
        check("48*x + 18*y", 48 * bezout.x + 18 * bezout.y, bezout.gcd);

        big_int a("123456789012345678901234567890");
        big_int b("987654321098765432109876543210");
        check("gcd == binary_gcd == ext_gcd (большие числа)",
              number_theory::gcd(a, b) == number_theory::binary_gcd(a, b) &&
                  number_theory::gcd(a, b) == number_theory::extended_gcd(a, b).gcd,
              true);

        std::cout << "\n< Степень по модулю >\n";
        check("3^13 mod 17", number_theory::mod_pow(3, 13, 17), 12);
        check("2^100 mod 1000000007", number_theory::mod_pow(2, 100, 1000000007), 976371285);

        std::cout << "\n< Символ Лежандра >\n";
        check("(2/7)", number_theory::legendre_symbol(2, 7), 1);
        check("(3/7)", number_theory::legendre_symbol(3, 7), -1);
        check("(14/7)", number_theory::legendre_symbol(14, 7), 0);

        std::cout << "\n< Символ Якоби >\n";
        check("(2/15)", number_theory::jacobi_symbol(2, 15), 1);
        check("(7/15)", number_theory::jacobi_symbol(7, 15), -1);
        check("(3/15)", number_theory::jacobi_symbol(3, 15), 0);
        check("(1001/9907)", number_theory::jacobi_symbol(1001, 9907), -1);

        std::cout << "\n< Функция Эйлера: три способа >\n";
        const int values[] = {1, 8, 9, 12, 13, 36, 100, 997};
        const int expected_phi[] = {1, 4, 6, 4, 12, 12, 40, 996};
        for (int i = 0; i < 8; ++i)
        {
            big_int n = values[i];
            big_int by_def = number_theory::euler_by_definition(n);
            big_int by_fact = number_theory::euler_by_factorization(n);
            big_int by_fourier = number_theory::euler_by_fourier(n);
            std::cout << "  n = " << n << ": определение = " << by_def << ", разложение = " << by_fact
                      << ", Фурье = " << by_fourier << "; ожидается " << expected_phi[i];
            bool ok = by_def == expected_phi[i] && by_fact == expected_phi[i] && by_fourier == expected_phi[i];
            if (!ok)
                ++failures;
            std::cout << (ok ? "  [ok]" : "  [FAIL]") << '\n';
        }

        bool all_equal = true;
        for (int n = 1; n <= 500; ++n)
        {
            big_int x = number_theory::euler_by_definition(n);
            if (x != number_theory::euler_by_factorization(n) || x != number_theory::euler_by_fourier(n))
                all_equal = false;
        }
        check_true("все три способа совпадают для n = 1..500", all_equal);

        std::cout << "\n< Функция Кармайкла >\n";
        const int c_values[] = {1, 2, 8, 9, 15, 16, 72, 561};
        const int c_expected[] = {1, 1, 2, 6, 4, 4, 6, 80};
        for (int i = 0; i < 8; ++i)
            check("lambda(" + std::to_string(c_values[i]) + ")", number_theory::carmichael(c_values[i]),
                  c_expected[i]);
    }

    namespace
    {
        void check_prime_test(const std::string& name, const i_prime_test& test)
        {
            std::cout << "\n< " << name << " (вероятность 0.9999) >\n";

            struct item { big_int n; bool prime; };
            const std::vector<item> items = {
                {-5, false}, {0, false}, {1, false}, {2, true}, {3, true}, {4, false},
                {9, false}, {17, true}, {41, true}, {97, true}, {100, false},
                {561, false},
                {1000000007, true},
                {big_int("2305843009213693951"), true},
                {big_int("2305843009213693953"), false},
            };

            for (const auto& it : items)
                check("is_prime(" + it.n.str() + ")", test.is_probably_prime(it.n, 0.9999), it.prime);
        }
    }

    void run_task2()
    {
        header("Пункт 2: вероятностные тесты простоты");

        check_prime_test("Ферма", fermat_test());
        check_prime_test("Соловей — Штрассен", solovay_strassen_test());
        check_prime_test("Миллер — Рабин", miller_rabin_test());

        std::cout << "\n< Некорректная вероятность >\n";
        bool thrown = false;
        try
        {
            miller_rabin_test().is_probably_prime(17, 1.0);
        }
        catch (const std::invalid_argument&)
        {
            thrown = true;
        }
        check_true("вероятность 1.0 -> исключение", thrown);
    }

    void run_task3()
    {
        header("Пункт 3: RSA");

        const std::pair<rsa::test_type, const char*> types[] = {
            {rsa::test_type::fermat, "Ферма"},
            {rsa::test_type::solovay_strassen, "Соловей — Штрассен"},
            {rsa::test_type::miller_rabin, "Миллер — Рабин"},
        };

        for (const auto& [type, name] : types)
        {
            rsa service(type, 0.999, 64);

            for (int generation = 1; generation <= 2; ++generation)
            {
                service.generate_keys();
                auto key = service.get_public_key();

                std::cout << "\n< RSA, тест: " << name << ", генерация " << generation << " >\n";
                std::cout << "  n = " << key.n << "\n  e = " << key.e << '\n';

                const big_int messages[] = {0, 1, 67, key.n - 1, random_between(0, key.n - 1)};
                for (const auto& m : messages)
                {
                    big_int c = service.encrypt(m);
                    big_int r = service.decrypt(c);
                    std::cout << "  m = " << m << ", c = " << c << ", расшифровано = " << r;
                    bool ok = (r == m);
                    if (!ok)
                        ++failures;
                    std::cout << (ok ? "  [ok]" : "  [FAIL]") << '\n';
                }
            }
        }
    }

    namespace
    {
        void print_attack(const weak_rsa_key& key, bool print_all_fractions)
        {
            std::cout << "  открытый ключ: n = " << key.n << ", e = " << key.e << '\n';
            std::cout << "  настоящее d = " << key.d << ", phi = " << key.phi << '\n';

            auto result = wiener_attack::attack(key.n, key.e);

            std::cout << "  подходящих дробей вычислено: " << result.convergents.size() << '\n';
            if (print_all_fractions)
            {
                for (const auto& [num, den] : result.convergents)
                    std::cout << "    " << num << "/" << den << '\n';
            }

            check_true("атака успешна", result.found);
            if (result.found)
            {
                std::cout << "  найденное d = " << result.d << ", найденное phi = " << result.phi << '\n';
                check_true("d и phi совпали с настоящими", result.d == key.d && result.phi == key.phi);
            }
        }
    }

    void run_task4()
    {
        header("Пункт 4: атака Винера");

        miller_rabin_test test;

        weak_key_generator small_generator(test, 0.9999, 24);
        for (int i = 1; i <= 2; ++i)
        {
            std::cout << "\n< Уязвимая пара " << i << " (простые по 24 бита) >\n";
            print_attack(small_generator.generate(), true);
        }

        weak_key_generator big_generator(test, 0.9999, 128);
        for (int i = 1; i <= 2; ++i)
        {
            std::cout << "\n< Уязвимая пара " << i << " (простые по 128 бит, модуль 256 бит) >\n";
            print_attack(big_generator.generate(), false);
        }

        std::cout << "\n< Ключи, сгенерированные сервисом RSA (защищены от атаки Винера) >\n";
        rsa service(rsa::test_type::miller_rabin, 0.9999, 64);
        for (int i = 1; i <= 3; ++i)
        {
            service.generate_keys();
            auto key = service.get_public_key();
            auto result = wiener_attack::attack(key.n, key.e);
            check_true("ключ " + std::to_string(i) + ": атака не нашла d", !result.found);
        }
    }
}
