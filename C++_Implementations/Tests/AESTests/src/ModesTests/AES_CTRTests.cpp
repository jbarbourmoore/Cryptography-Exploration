#include <gtest/gtest.h>  
#include <cstdio>

#include "AES_CTR.hpp"


TEST(AES_CTR_Tests, aes128_ctr_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "874D6191B620E3261BEF6864990DB6CE9806F66B7970FDFF8617187BB9FFFDFF5AE4DF3EDBD5D35E5B4F09020DB03EAB1E031DDA2FBE03D1792170A0F3009CEE";
    std::string initialization_vector = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    unsigned char key_128[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_CTR::AES128Cypher(given_plain_string, key_128, initialization_vector);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_plain_text = AES_CTR::AES128InvCypher(actual_cypher_text, key_128, initialization_vector);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}