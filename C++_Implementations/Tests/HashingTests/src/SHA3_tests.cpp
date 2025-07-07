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

TEST(SHA3_Tests, sha3_384_5_bit_input) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_Msg5.pdf
    

    std:vector<bool> input_bits = {true, true, false, false, true};
    std::string expected_result = "73 7C 9B 49 18 85 E9 BF 74 28 E7 92 74 1A 7B F8 DC A9 65 34 71 C3 E1 48 47 3F 2C 23 6B 6A 0A 64 55 EB 1D CE 9F 77 9B 4B 6B 23 7F EF 17 1B 1C 64";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHA3_384::hashAsHex(input_bits);
    
    EXPECT_EQ(expected_result, hex_result);
}

TEST(SHA3_Tests, sha3_384_30_bit_input) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_Msg30.pdf
    
    std:vector<bool> input_bits = {1,1,0,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,0,0,1,1,0};
    std::string expected_result = "95 5B 4D D1 BE 03 26 1B D7 6F 80 7A 7E FD 43 24 35 C4 17 36 28 11 B8 A5 0C 56 4E 7E E9 58 5E 1A C7 62 6D DE 2F DC 03 0F 87 61 96 EA 26 7F 08 C3";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHA3_384::hashAsHex(input_bits);
    
    EXPECT_EQ(expected_result, hex_result);
}

TEST(SHA3_Tests, sha3_512_5_bit_input) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg5.pdf
    
    std:vector<bool> input_bits = {true, true, false, false, true};
    std::string expected_result = "A1 3E 01 49 41 14 C0 98 00 62 2A 70 28 8C 43 21 21 CE 70 03 9D 75 3C AD D2 E0 06 E4 D9 61 CB 27 54 4C 14 81 E5 81 4B DC EB 53 BE 67 33 D5 E0 99 79 5E 5E 81 91 8A DD B0 58 E2 2A 9F 24 88 3F 37";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHA3_512::hashAsHex(input_bits);
    
    EXPECT_EQ(expected_result, hex_result);
}

TEST(SHA3_Tests, sha3_512_30_bit_input) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg30.pdf

    std:vector<bool> input_bits = {1,1,0,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,0,0,1,1,0};
    std::string expected_result = "98 34 C0 5A 11 E1 C5 D3 DA 9C 74 0E 1C 10 6D 9E 59 0A 0E 53 0B 6F 6A AA 78 30 52 5D 07 5C A5 DB 1B D8 A6 AA 98 1A 28 61 3A C3 34 93 4A 01 82 3C D4 5F 45 E4 9B 6D 7E 69 17 F2 F1 67 78 06 7B AB";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHA3_512::hashAsHex(input_bits);
    
    EXPECT_EQ(expected_result, hex_result);
}