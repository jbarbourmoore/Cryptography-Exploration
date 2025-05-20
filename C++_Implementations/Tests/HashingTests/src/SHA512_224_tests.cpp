#include <gtest/gtest.h>  
#include <stddef.h>

#include "SHA_64bit.hpp"

TEST(SHA512_224_Tests, sha512_224_with_1_message_block) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf

    SHA512_224 sha512_224 = SHA512_224();
    string string_input = "abc";
    string hex_result = sha512_224.hashString(string_input);
    string expected = "4634270F707B6A54 DAAE7530460842E2 0E37ED265CEEE9A4 3E8924AA";
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str(), hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}

TEST(SHA512_224_Tests, sha512_224_with_2_message_blocks) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
    
    SHA512_224 sha512_224 = SHA512_224();
    string string_input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    string expected = "23FEC5BB94D60B23 308192640B0C4533 35D664734FE40E72 68674AF9";
    string hex_result = sha512_224.hashString(string_input);
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str() , hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}