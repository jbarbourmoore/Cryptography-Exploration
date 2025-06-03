#include "AES_GCM.hpp"

#include <gtest/gtest.h>  
#include <cstdio>

TEST(AES_GCM_Tests, ghash_test) {

    std::string key = "00000000000000000000000000000000";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_128;

    AESDataBlock first_block = AESDataBlock("0388DACE60B6A392F328C2B971B2FE78");
    AESDataBlock second_block = AESDataBlock("00000000000000000000000000000080");
    std::vector<AESDataBlock> input_blocks;
    input_blocks.push_back(first_block);
    input_blocks.push_back(second_block);

    std::string expected_ghash_string = "F38CBB1AD69223DCC3457AE5B6B0F885";
    AESDataBlock expected_block = AESDataBlock(expected_ghash_string);
    std::vector<AESWord> expanded_key = AESKey::keyExpansion(key);

    AESDataBlock hash_block = AESDataBlock("66E94BD4EF8A2C3B884CFA59CA342B2E");

    AESDataBlock result_block = AES_GCM::GHASH(hash_block, input_blocks);

    EXPECT_EQ(result_block, expected_block);

}