cmake_minimum_required(VERSION 3.20)
project(lab2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

find_package(Boost 1.70 REQUIRED)

add_executable(main
    app/main.cpp
    app/tests.cpp
    src/number_theory.cpp
    src/random.cpp
    src/prime_test.cpp
    src/fermat_test.cpp
    src/solovay_strassen_test.cpp
    src/miller_rabin_test.cpp
    src/prime_generation.cpp
    src/rsa.cpp
    src/wiener_attack.cpp
)

target_include_directories(main PRIVATE include app)
target_link_libraries(main PRIVATE Boost::headers)
target_compile_options(main PRIVATE -Wall -Wextra)
