#include <gtest/gtest.h>  
#include <stddef.h>

#include "SHA_32bit.hpp"

TEST(SHA224_Tests, sha224_with_1_message_block) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf

    SHA224 sha224 = SHA224();
    string string_input = "abc";
    string hex_result = sha224.hashString(string_input);
    string expected = "23097D22 3405D822 8642A477 BDA255B3 2AADBCE4 BDA0B3F7 E36C9DA7";

    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str(), hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}

TEST(SHA224_Tests, sha224_with_2_message_blocks) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
    
    SHA224 sha224 = SHA224();
    string string_input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    string expected = "75388B16 512776CC 5DBA5DA1 FD890150 B0C6455C B4F58B19 52522525";
    string hex_result = sha224.hashString(string_input);

    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str() , hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);
}