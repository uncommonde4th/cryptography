cmake_minimum_required(VERSION 3.25)

project(lab1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(PROJECT_SOURCES
    src/bit_utils.cpp
    src/cipher_context.cpp
    src/feistel_network.cpp
    src/des.cpp
)

find_package(Threads REQUIRED)

add_executable(main
    src/main.cpp
    ${PROJECT_SOURCES}
)

target_include_directories(main PUBLIC include)
target_link_libraries(main PRIVATE Threads::Threads)
target_compile_options(main PRIVATE -Wall -Wextra -Wpedantic)