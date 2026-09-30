cmake_minimum_required(VERSION 3.25)

project(lab1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(PROJECT_SOURCES
    src/bit_utils.cpp
)

add_executable(main
    src/main.cpp
    ${PROJECT_SOURCES}
)

target_include_directories(main PUBLIC include)
target_compile_options(main PRIVATE -Wall -Wextra -Wpedantic)