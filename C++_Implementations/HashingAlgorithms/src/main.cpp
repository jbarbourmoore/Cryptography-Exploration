/// This is my main method for SHA Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/19/25

#include "SHA_64bit.hpp"

int main(int argc, char const *argv[])
{
    SHA512 sha512 = SHA512();
    string string_input = "abc";
    string hex_result = sha512.hashString(string_input);
    printf("hash digest : %s\n", hex_result.c_str());
    return 0;
}