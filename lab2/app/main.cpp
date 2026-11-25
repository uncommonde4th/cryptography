#include <exception>
#include <iostream>

#include "tests.hpp"

int main()
{
    try
    {
        lab2::tests::run_task1();
        lab2::tests::run_task2();
        lab2::tests::run_task3();
        lab2::tests::run_task4();
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Ошибка: " << ex.what() << '\n';
        return 1;
    }

    std::cout << "\n=== Итого непройденных проверок: " << lab2::tests::failed_checks() << " ===\n";
    return lab2::tests::failed_checks() == 0 ? 0 : 2;
}
