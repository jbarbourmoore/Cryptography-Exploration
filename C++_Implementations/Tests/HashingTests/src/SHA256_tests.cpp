#include <gtest/gtest.h>  
#include <stddef.h>

#include "SHA2.hpp"

TEST(SHA256_Tests, sha256_with_1_message_block) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf

    string string_input = "abc";
    string expected = "BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD";
    message string_to_message = SHA256::padStringToMessage(string_input);
    string hex_result = SHA256::messageToHexString(string_to_message);
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str(), hex_result.c_str());
    hex_result = SHA256::hashMessageToHex(string_to_message);
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}

TEST(SHA256_Tests, sha256_with_2_message_blocks) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
    
    string string_input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    string expected = "248D6A61 D20638B8 E5C02693 0C3E6039 A33CE459 64FF2167 F6ECEDD4 19DB06C1";
    message string_to_message = SHA256::padStringToMessage(string_input);
    string hex_result = SHA256::messageToHexString(string_to_message);
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str() , hex_result.c_str());
    hex_result = SHA256::hashMessageToHex(string_to_message);
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}