/// This is my main method for SHA Experimentation in C++
///
/// Author        : Jamie Barbour-Moore
/// Created       : 05/19/25

#include "CreateHashDigest.hpp"
#include "SHA3.hpp"

int main(int argc, char const *argv[])
{
    string string_input = "abc";
    string hex_result = CreateHashDigest::fromString(string_input, HashType::SHA1_DIGEST);
    printf("SHA1 digest       : %s\n", hex_result.c_str());
    hex_result = CreateHashDigest::fromString(string_input, HashType::SHA224_DIGEST);
    printf("SHA224 digest     : %s\n", hex_result.c_str());
    hex_result = CreateHashDigest::fromString(string_input, HashType::SHA256_DIGEST);
    printf("SHA256 digest     : %s\n", hex_result.c_str());
    hex_result = CreateHashDigest::fromString(string_input, HashType::SHA384_DIGEST);
    printf("SHA384 digest     : %s\n", hex_result.c_str());
    hex_result = CreateHashDigest::fromString(string_input, HashType::SHA512_DIGEST);
    printf("SHA512 digest     : %s\n", hex_result.c_str());
    hex_result = CreateHashDigest::fromString(string_input, HashType::SHA512_224_DIGEST);
    printf("SHA512/224 digest : %s\n", hex_result.c_str());
    hex_result = CreateHashDigest::fromString(string_input, HashType::SHA512_256_DIGEST);
    printf("SHA512/256 digest : %s\n", hex_result.c_str());

    SHA3_State state = SHA3_State();
    state.printBits();
    state.printHex();

    std::string hex_input = "9876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210";
    SHA3_State state_two = SHA3_State(hex_input);
    state_two.printBits();
    state_two.printHex();
    
    return 0;
}