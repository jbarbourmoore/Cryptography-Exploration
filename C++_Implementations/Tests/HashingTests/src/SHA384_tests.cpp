#include <gtest/gtest.h>  
#include <stddef.h>

#include "SHA_64bit.hpp"

TEST(SHA384_Tests, sha382_with_1_message_block) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf

    SHA384 sha384 = SHA384();
    string string_input = "abc";
    string hex_result = sha384.hashString(string_input);
    string expected = "CB00753F45A35E8B B5A03D699AC65007 272C32AB0EDED163 1A8B605A43FF5BED 8086072BA1E7CC23 58BAECA134C825A7";
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str(), hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}

TEST(SHA384_Tests, sha384_with_2_message_blocks) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf
    
    SHA384 sha384 = SHA384();
    string string_input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    string expected = "09330C33F71147E8 3D192FC782CD1B47 53111B173B3B05D2 2FA08086E3B0F712 FCC7C71A557E2DB9 66C3E9FA91746039";
    string hex_result = sha384.hashString(string_input);
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str() , hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}