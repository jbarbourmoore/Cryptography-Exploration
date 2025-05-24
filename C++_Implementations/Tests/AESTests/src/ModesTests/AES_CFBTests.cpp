#include <gtest/gtest.h>  
#include <cstdio>

#include "AES_CFB.hpp"


TEST(AES_CFB_Tests, aes128_cfb_s8_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "3B79424C9C0DD436BACE9E0ED4586A4F32B9DED50AE3BA69D472E88267FB505270CBAD1E257691F7C47C5038297EDDA32FF26D0ED19174096161ECC14086DD62";
    std::string initialization_vector = "000102030405060708090a0b0c0d0e0f";
    unsigned char key_128[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_CFB::AES128Cypher(given_plain_string, key_128, initialization_vector, 8);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_plain_text = AES_CFB::AES128InvCypher(actual_cypher_text, key_128, initialization_vector, 8);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}

TEST(AES_CFB_Tests, aes128_cfb_s1_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "68B3A264F838F5F8C3101070D1AB4C2E22E7F950383A0B71ADE4FAD0095CB188A57972C3C1882615F7511411FBEBF1193997069704FC1D1F27028434C99E60F4";
    std::string initialization_vector = "000102030405060708090a0b0c0d0e0f";
    unsigned char key_128[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_CFB::AES128Cypher(given_plain_string, key_128, initialization_vector, 1);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_plain_text = AES_CFB::AES128InvCypher(actual_cypher_text, key_128, initialization_vector, 1);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}

TEST(AES_CFB_Tests, aes128_cfb_s128_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "3B3FD92EB72DAD20333449F8E83CFB4AC8A64537A0B3A93FCDE3CDAD9F1CE58B26751F67A3CBB140B1808CF187A4F4DFC04B05357C5D1C0EEAC4C66F9FF7F2E6";
    std::string initialization_vector = "000102030405060708090a0b0c0d0e0f";
    unsigned char key_128[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_CFB::AES128Cypher(given_plain_string, key_128, initialization_vector, 128);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 128\n");
    std::vector<AESDataBlock> actual_plain_text = AES_CFB::AES128InvCypher(actual_cypher_text, key_128, initialization_vector, 128);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}

TEST(AES_CFB_Tests, aes192_cfb_s8_test) {
    std::string given_plain_string = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    std::string given_cypher_string = "CDA2521EF0A905CA44CD057CBF0D47A0678A7BCFB6AEAA3047B38936021F48BBB63CEFDAC02B2E840904EFCE6F4326BE228683739063DC30E937FFEDD63E3C94";
    std::string initialization_vector = "000102030405060708090a0b0c0d0e0f";
    int s_bits = 8;
    unsigned char key_192[24] = {0x8e ,0x73 ,0xb0 ,0xf7 ,0xda ,0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
    
    std::vector<AESDataBlock> given_plain_text = AESDataBlock::dataBlocksFromHexString(given_plain_string);
    std::vector<AESDataBlock> given_cypher_text = AESDataBlock::dataBlocksFromHexString(given_cypher_string);

    printf("\nCypher Result With AES 128 (CFB 8 bit)\n");
    std::vector<AESDataBlock> actual_cypher_text = AES_CFB::AES192Cypher(given_plain_string, key_192, initialization_vector, s_bits);
    for(int i = 0 ; i < actual_cypher_text.size() ; i ++){
        actual_cypher_text.at(i).print();
    }
    printf("Inverse Cypher Result With AES 192 (CFB 8 bit)\n");
    std::vector<AESDataBlock> actual_plain_text = AES_CFB::AES192InvCypher(actual_cypher_text, key_192, initialization_vector, s_bits);
    for(int i = 0 ; i < actual_plain_text.size() ; i ++){
        actual_plain_text.at(i).print();
    }

    EXPECT_EQ(actual_cypher_text, given_cypher_text);
    EXPECT_EQ(actual_plain_text, given_plain_text);
}