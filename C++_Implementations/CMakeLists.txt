cmake_minimum_required(VERSION 4.0.2)

project(CyptographyExporation VERSION 1.0
                    DESCRIPTION "Exploring Cryptography algorithms in C++"
                    LANGUAGES CXX)

message("C++ Compiler ${CMAKE_CXX_COMPILER}")
message("C++ Compiler Version ${CMAKE_CXX_COMPILER_VERSION}")

set (CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)

add_subdirectory(RSA)
add_subdirectory(HelperFunctions)