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


TEST(AES_CTR_Tests, aes192_ctr_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "1ABC932417521CA24F2B0459FE7E6E0B090339EC0AA6FAEFD5CCC2C6F4CE8E941E36B26BD1EBC670D1BD1D665620ABF74F78A7F6D29809585A97DAEC58C6B050";
    std::string initialization_vector = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    unsigned char key_192[24] = {0x8e ,0x73 ,0xb0 ,0xf7 ,0xda ,0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 192\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_CTR::AES192Cypher(given_plain_string, key_192, initialization_vector);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 192\n");
    std::vector<AESDataBlock> actual_plain_text = AES_CTR::AES192InvCypher(actual_cypher_text, key_192, initialization_vector);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}

TEST(AES_CTR_Tests, aes256_ctr_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C52B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6";
    std::string initialization_vector = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    unsigned char key_256[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 256\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_CTR::AES256Cypher(given_plain_string, key_256, initialization_vector);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 256\n");
    std::vector<AESDataBlock> actual_plain_text = AES_CTR::AES256InvCypher(actual_cypher_text, key_256, initialization_vector);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}