cmake_minimum_required(VERSION 4.0.2)

project(CyptographyExporation VERSION 1.0
                    DESCRIPTION "Exploring Cryptography algorithms in C++"
                    LANGUAGES CXX)

find_package(OpenSSL REQUIRED)

add_subdirectory(RSA)