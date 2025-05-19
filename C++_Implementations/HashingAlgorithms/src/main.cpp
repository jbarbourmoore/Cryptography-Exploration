/// This is my main method for SHA Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/19/25

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include "SHA1.hpp"

int main(int argc, char const *argv[])
{
    printf("u_int32_t: %ld\nu_int64_t: %ld\n", sizeof(u_int32_t), sizeof(u_int64_t));

    word input = 5;
    word rotr_output = SHA1::ROTR(input, 1);
    word rotl_output = SHA1::ROTL(input, 1);
    printf("input : %u, right rotate 1 output : %u\n",input, rotr_output);
    printf("input : %u,  left rotate 1 output : %u\n",input, rotl_output);

    return 0;
}