#include <gtest/gtest.h>  
#include <stddef.h>

#include "SHA_64bit.hpp"

TEST(SHA512_256_Tests, sha512_256_with_1_message_block) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf

    SHA512_256 sha512_256 = SHA512_256();
    string string_input = "abc";
    string hex_result = sha512_256.hashString(string_input);
    string expected = "53048E2681941EF9 9B2E29B76B4C7DAB E4C2D0C634FC6D46 E0E2F13107E7AF23";
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str(), hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}

TEST(SHA512_256_Tests, sha512_256_with_2_message_blocks) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
    
    SHA512_256 sha512_256 = SHA512_256();
    string string_input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    string expected = "3928E184FB8690F8 40DA3988121D31BE 65CB9D3EF83EE614 6FEAC861E19B563A";
    string hex_result = sha512_256.hashString(string_input);
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str() , hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}