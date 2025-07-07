#include <gtest/gtest.h>  
#include <stddef.h>

#include "SHA3.hpp"


TEST(SHA3_Tests, sha3_224_5_bit_input) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
    

    std:vector<bool> input_bits = {true, true, false, false, true};
    std::string expected_result = "FF BA D5 DA 96 BA D7 17 89 33 02 06 DC 67 68 EC AE B1 B3 2D CA 6B 33 01 48 96 74 AB";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHA3_224::hashAsHex(input_bits);
    
    EXPECT_EQ(expected_result, hex_result);
}

TEST(SHA3_Tests, sha3_224_30_bit_input) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg30.pdf
    
    std:vector<bool> input_bits = {1,1,0,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,0,0,1,1,0};
    std::string expected_result = "D6 66 A5 14 CC 9D BA 25 AC 1B A6 9E D3 93 04 60 DE AA C9 85 1B 5F 0B AA B0 07 DF 3B";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHA3_224::hashAsHex(input_bits);
    
    EXPECT_EQ(expected_result, hex_result);
}

TEST(SHA3_Tests, sha3_256_5_bit_input) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg5.pdf
    
    std:vector<bool> input_bits = {true, true, false, false, true};
    std::string expected_result = "7B 00 47 CF 5A 45 68 82 36 3C BF 0F B0 53 22 CF 65 F4 B7 05 9A 46 36 5E 83 01 32 E3 B5 D9 57 AF";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHA3_256::hashAsHex(input_bits);
    
    EXPECT_EQ(expected_result, hex_result);
}

TEST(SHA3_Tests, sha3_256_30_bit_input) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg30.pdf

    std:vector<bool> input_bits = {1,1,0,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,0,0,1,1,0};
    std::string expected_result = "C8 24 2F EF 40 9E 5A E9 D1 F1 C8 57 AE 4D C6 24 B9 2B 19 80 9F 62 AA 8C 07 41 1C 54 A0 78 B1 D0";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHA3_256::hashAsHex(input_bits);
    
    EXPECT_EQ(expected_result, hex_result);
}