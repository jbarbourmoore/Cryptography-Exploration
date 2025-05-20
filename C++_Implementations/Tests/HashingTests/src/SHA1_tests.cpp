#include <gtest/gtest.h>  
#include <stddef.h>

#include "SHA_32bit.hpp"

TEST(SHA1_Tests, sha1_with_1_message_block) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
    SHA1 sha1 = SHA1();
    string string_input = "abc";
    string hex_result = sha1.hashString(string_input);
    string expected = "A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D";
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str(), hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}
TEST(SHA1_Tests, sha1_with_2_message_blocks) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
    
    string string_input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    string expected = "84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1";
    SHA1 sha1 = SHA1();
    string hex_result = sha1.hashString(string_input);
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str() , hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}