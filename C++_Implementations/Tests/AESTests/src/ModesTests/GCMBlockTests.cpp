#include "AESDataBlock.hpp"

#include <gtest/gtest.h>  
#include <cstdio>

TEST(AESGCMBlock_Tests, galois_mult_test_1){
    std::string original_hex = "00000000000000000000000000AABBCC";
    AESDataBlock block1 = AESDataBlock(original_hex);
    AESDataBlock block2 = AESDataBlock(original_hex);
    AESDataBlock block3 = AESDataBlock::galoisMultiplication(block1, block2);
    block3.print();
    std::string expected_result = "70800000000000000000EFFFFC784D99";
    AESDataBlock expected_block = AESDataBlock(expected_result);
    EXPECT_EQ(expected_block, block3);
}

TEST(AESGCMBlock_Tests, galois_mult_test_2){
    std::string original_hex = "00000000000000000000000000AABBCC";
    std::string second_hex = "70800000000000000000EFFFFC784D99";
    AESDataBlock block1 = AESDataBlock(original_hex);
    AESDataBlock block2 = AESDataBlock(second_hex);
    AESDataBlock block3 = AESDataBlock::galoisMultiplication(block1, block2);
    block3.print();
    std::string expected_result = "BCF8000000000082957CEBF07A56F858";
    AESDataBlock expected_block = AESDataBlock(expected_result);
    EXPECT_EQ(expected_block, block3);
}