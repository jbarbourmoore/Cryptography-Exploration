#include <gtest/gtest.h>  
#include <cstdio>

#include "AES_OFB.hpp"


TEST(AES_OFB_Tests, aes128_ofb_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "3B3FD92EB72DAD20333449F8E83CFB4A7789508D16918F03F53C52DAC54ED8259740051E9C5FECF64344F7A82260EDCC304C6528F659C77866A510D9C1D6AE5E";
    std::string initialization_vector = "000102030405060708090a0b0c0d0e0f";
    unsigned char key_128[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_OFB::AES128Cypher(given_plain_string, key_128, initialization_vector);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_plain_text = AES_OFB::AES128InvCypher(actual_cypher_text, key_128, initialization_vector);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}

TEST(AES_OFB_Tests, aes192_ofb_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "CDC80D6FDDF18CAB34C25909C99A4174FCC28B8D4C63837C09E81700C11004018D9A9AEAC0F6596F559C6D4DAF59A5F26D9F200857CA6C3E9CAC524BD9ACC92A";
    std::string initialization_vector = "000102030405060708090a0b0c0d0e0f";
    unsigned char key_192[24] = {0x8e ,0x73 ,0xb0 ,0xf7 ,0xda ,0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 192\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_OFB::AES192Cypher(given_plain_string, key_192, initialization_vector);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 192\n");
    std::vector<AESDataBlock> actual_plain_text = AES_OFB::AES192InvCypher(actual_cypher_text, key_192, initialization_vector);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}


TEST(AES_OFB_Tests, aes256_ofb_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "DC7E84BFDA79164B7ECD8486985D38604FEBDC6740D20B3AC88F6AD82A4FB08D71AB47A086E86EEDF39D1C5BBA97C4080126141D67F37BE8538F5A8BE740E484";
    std::string initialization_vector = "000102030405060708090a0b0c0d0e0f";
    unsigned char key_256[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 256\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_OFB::AES256Cypher(given_plain_string, key_256, initialization_vector);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 256\n");
    std::vector<AESDataBlock> actual_plain_text = AES_OFB::AES256InvCypher(actual_cypher_text, key_256, initialization_vector);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}