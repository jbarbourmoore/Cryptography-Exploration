cmake_minimum_required(VERSION 4.0.2)

project(CyptographyExporation VERSION 1.0
                    DESCRIPTION "Exploring Cryptography algorithms in C++"
                    LANGUAGES CXX)

message("C++ Compiler ${CMAKE_CXX_COMPILER}")
message("C++ Compiler Version ${CMAKE_CXX_COMPILER_VERSION}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_subdirectory(RSA)
add_subdirectory(HashingAlgorithms)
add_subdirectory(HelperFunctions)
add_subdirectory(Tests)

include(CTest)
