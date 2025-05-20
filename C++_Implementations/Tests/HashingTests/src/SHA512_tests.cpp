#include <gtest/gtest.h>  
#include <stddef.h>

#include "SHA_64bit.hpp"

TEST(SHA512_Tests, sha512_with_1_message_block) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf

    SHA512 sha512 = SHA512();
    string string_input = "abc";
    string hex_result = sha512.hashString(string_input);
    string expected = "DDAF35A193617ABA CC417349AE204131 12E6FA4E89A97EA2 0A9EEEE64B55D39A 2192992A274FC1A8 36BA3C23A3FEEBBD 454D4423643CE80E 2A9AC94FA54CA49F";
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str(), hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}

TEST(SHA512_Tests, sha512_with_2_message_blocks) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
    
    SHA512 sha512 = SHA512();
    string string_input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    string expected = "8E959B75DAE313DA 8CF4F72814FC143F 8F7779C6EB9F7FA1 7299AEADB6889018 501D289E4900F7E4 331B99DEC4B5433A C7D329EEB6DD2654 5E96E55B874BE909";
    string hex_result = sha512.hashString(string_input);
    printf("\ninput : %s\nmessage string : \n%s\n",string_input.c_str() , hex_result.c_str());
    printf("hash digest : %s\n", hex_result.c_str());

    EXPECT_EQ(expected, hex_result);

}