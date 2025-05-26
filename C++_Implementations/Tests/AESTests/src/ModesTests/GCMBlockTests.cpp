#include "GCMBlock.hpp"

#include <gtest/gtest.h>  
#include <cstdio>

TEST(AESGCMBlock_Tests, hex_string_conversions_test){
    std::string original_hex = "01DFF12345FFABC1111222FF72534295";
    GCMBlock block = GCMBlock(original_hex);
    std::string retrieved_hex = block.getHexString();
    block.print();
    EXPECT_EQ(original_hex, retrieved_hex);
}
TEST(AESGCMBlock_Tests, hex_string_conversions_test_2){
    std::string original_hex = "00000000001000000100000000000000";
    GCMBlock block = GCMBlock(original_hex);
    std::string retrieved_hex = block.getHexString();
    block.print();
    EXPECT_EQ(original_hex, retrieved_hex);
}

TEST(AESGCMBlock_Tests, galois_mult_test_1){
    std::string original_hex = "00000000000000000000000000AABBCC";
    GCMBlock block1 = GCMBlock(original_hex);
    GCMBlock block2 = GCMBlock(original_hex);
    GCMBlock block3 = GCMBlock::galoisMultiplication(block1, block2);
    std::string retrieved_hex = block3.getHexString();
    block3.print();
    std::string expected_result = "70800000000000000000EFFFFC784D99";
    EXPECT_EQ(expected_result, retrieved_hex);
}

TEST(AESGCMBlock_Tests, galois_mult_test_2){
    std::string original_hex = "00000000000000000000000000AABBCC";
    std::string second_hex = "70800000000000000000EFFFFC784D99";
    GCMBlock block1 = GCMBlock(original_hex);
    GCMBlock block2 = GCMBlock(second_hex);
    GCMBlock block3 = GCMBlock::galoisMultiplication(block1, block2);
    std::string retrieved_hex = block3.getHexString();
    block3.print();
    std::string expected_result = "BCF8000000000082957CEBF07A56F858";
    EXPECT_EQ(expected_result, retrieved_hex);
}