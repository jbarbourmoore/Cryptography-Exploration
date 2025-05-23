#include <gtest/gtest.h>  
#include <cstdio>

#include "AES_CBC.hpp"


TEST(AES_CBC_Tests, aes128_cbc_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "7649ABAC8119B246CEE98E9B12E9197D5086CB9B507219EE95DB113A917678B273BED6B8E3C1743B7116E69E222295163FF1CAA1681FAC09120ECA307586E1A7";
    std::string initialization_vector = "000102030405060708090a0b0c0d0e0f";
    unsigned char key_128[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_CBC::AES128Cypher(given_plain_string, key_128, initialization_vector);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_plain_text = AES_CBC::AES128InvCypher(actual_cypher_text, key_128, initialization_vector);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}

TEST(AES_CBC_Tests, aes192_cbc_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "4F021DB243BC633D7178183A9FA071E8B4D9ADA9AD7DEDF4E5E738763F69145A571B242012FB7AE07FA9BAAC3DF102E008B0E27988598881D920A9E64F5615CD";
    std::string initialization_vector = "000102030405060708090a0b0c0d0e0f";
    unsigned char key_192[24] = {0x8e ,0x73 ,0xb0 ,0xf7 ,0xda ,0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 192\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_CBC::AES192Cypher(given_plain_string, key_192, initialization_vector);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 192\n");
    std::vector<AESDataBlock> actual_plain_text = AES_CBC::AES192InvCypher(actual_cypher_text, key_192, initialization_vector);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}

TEST(AES_CBC_Tests, aes256_cbc_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D39F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B";
    std::string initialization_vector = "000102030405060708090a0b0c0d0e0f";
    unsigned char key_256[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 256\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_CBC::AES256Cypher(given_plain_string, key_256, initialization_vector);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 256\n");
    std::vector<AESDataBlock> actual_plain_text = AES_CBC::AES256InvCypher(actual_cypher_text, key_256, initialization_vector);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}