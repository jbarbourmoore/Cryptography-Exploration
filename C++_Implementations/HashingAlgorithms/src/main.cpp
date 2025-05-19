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

    word hex_to_word_result = SHA1::hexStringToWord("FF");
    printf("input : FF, word  : %u\n", hex_to_word_result);
    string hex_result = SHA1::wordToHexString(hex_to_word_result);
    printf("input : %u, string : %s\n", hex_to_word_result, hex_result.c_str());

    hex_to_word_result = SHA1::hexStringToWord("FFFFFFFF");
    printf("input : FFFFFFFF, word : %u\n", hex_to_word_result);
    hex_result = SHA1::wordToHexString(hex_to_word_result);
    printf("input : %u, string : %s\n", hex_to_word_result, hex_result.c_str());

    hex_to_word_result ++;
    printf("max_value plus 1 : %u\n", hex_to_word_result);
    hex_result = SHA1::wordToHexString(hex_to_word_result);
    printf("input : %u, string : %s\n", hex_to_word_result, hex_result.c_str());

    vector<bool> vector_of_bool = {true,true,false,true};
    message vector_to_message = SHA1::padVectorBoolInput(vector_of_bool);
    hex_result = SHA1::messageToHexString(vector_to_message);
    printf("message string : %s\n", hex_result.c_str());

    hex_result = SHA1::hashMessageToHex(vector_to_message);
    printf("hash digest : %s\n", hex_result.c_str());

    string string_input = "abc";
    message string_to_message = SHA1::padStringToMessage(string_input);
    hex_result = SHA1::messageToHexString(string_to_message);
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str(), hex_result.c_str());
    hex_result = SHA1::hashMessageToHex(string_to_message);
    printf("hash digest : %s\n", hex_result.c_str());

    string_input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    string_to_message = SHA1::padStringToMessage(string_input);
    hex_result = SHA1::messageToHexString(string_to_message);
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str() , hex_result.c_str());
    hex_result = SHA1::hashMessageToHex(string_to_message);
    printf("hash digest : %s\n", hex_result.c_str());

    return 0;
}