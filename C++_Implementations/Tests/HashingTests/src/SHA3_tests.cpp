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

TEST(SHA3_Tests, SHAKE128_5_bit_input_4096bits) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg5.pdf
    
    std:vector<bool> input_bits = {true, true, false, false, true};
    int digest_length = 4096;

    std::string expected_result = "2E 0A BF BA 83 E6 72 0B FB C2 25 FF 6B 7A B9 FF CE 58 BA 02 7E E3 D8 98 76 4F EF 28 7D DE CC CA 3E 6E 59 98 41 1E 7D DB 32 F6 75 38 F5 00 B1 8C 8C 97 C4 52 C3 70 EA 2C F0 AF CA 3E 05 DE 7E 4D E2 7F A4 41 A9 CB 34 FD 17 C9 78 B4 2D 5B 7E 7F 9A B1 8F FE FF C3 C5 AC 2F 3A 45 5E EB FD C7 6C EA EB 0A 2C CA 22 EE F6 E6 37 F4 CA BE 5C 51 DE D2 E3 FA D8 B9 52 70 A3 21 84 56 64 F1 07 D1 64 96 BB 7A BF BE 75 04 B6 ED E2 E8 9E 4B 99 6F B5 8E FD C4 18 1F 91 63 38 1C BE 7B C0 06 A7 A2 05 98 9C 52 6C D1 BD 68 98 36 93 B4 BD C5 37 28 B2 41 C1 CF F4 2B B6 11 50 2C 35 20 5C AB B2 88 75 56 55 D6 20 C6 79 94 F0 64 51 18 7F 6F D1 7E 04 66 82 BA 12 86 06 3F F8 8F E2 50 8D 1F CA F9 03 5A 12 31 AD 41 50 A9 C9 B2 4C 9B 2D 66 B2 AD 1B DE 0B D0 BB CB 8B E0 5B 83 52 29 EF 79 19 73 73 23 42 44 01 E1 D8 37 B6 6E B4 E6 30 FF 1D E7 0C B3 17 C2 BA CB 08 00 1D 34 77 B7 A7 0A 57 6D 20 86 90 33 58 9D 85 A0 1D DB 2B 66 46 C0 43 B5 9F C0 11 31 1D A6 66 FA 5A D1 D6 38 7F A9 BC 40 15 A3 8A 51 D1 DA 1E A6 1D 64 8D C8 E3 9A 88 B9 D6 22 BD E2 07 FD AB C6 F2 82 7A 88 0C 33 0B BF 6D F7 33 77 4B 65 3E 57 30 5D 78 DC E1 12 F1 0A 2C 71 F4 CD AD 92 ED 11 3E 1C EA 63 B9 19 25 ED 28 19 1E 6D BB B5 AA 5A 2A FD A5 1F C0 5A 3A F5 25 8B 87 66 52 43 55 0F 28 94 8A E2 B8 BE B6 BC 9C 77 0B 35 F0 67 EA A6 41 EF E6 5B 1A 44 90 9D 1B 14 9F 97 EE A6 01 39 1C 60 9E C8 1D 19 30 F5 7C 18 A4 E0 FA B4 91 D1 CA DF D5 04 83 44 9E DC 0F 07 FF B2 4D 2C 6F 9A 9A 3B FF 39 AE 3D 57 F5 60 65 4D 7D 75 C9 08 AB E6 25 64 75 3E AC 39 D7 50 3D A6 D3 7C 2E 32 E1 AF 3B 8A EC 8A E3 06 9C D9";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHAKE128::hashAsHex(input_bits, digest_length);
    printf("digest size : %ld \n", expected_result.size() * 4);
    EXPECT_EQ(expected_result, hex_result);
}

TEST(SHA3_Tests, SHAKE128_5_bit_input_2048bits) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg5.pdf
    
    std:vector<bool> input_bits = {true, true, false, false, true};
    int digest_length = 2048;

    std::string expected_result = "2E 0A BF BA 83 E6 72 0B FB C2 25 FF 6B 7A B9 FF CE 58 BA 02 7E E3 D8 98 76 4F EF 28 7D DE CC CA 3E 6E 59 98 41 1E 7D DB 32 F6 75 38 F5 00 B1 8C 8C 97 C4 52 C3 70 EA 2C F0 AF CA 3E 05 DE 7E 4D E2 7F A4 41 A9 CB 34 FD 17 C9 78 B4 2D 5B 7E 7F 9A B1 8F FE FF C3 C5 AC 2F 3A 45 5E EB FD C7 6C EA EB 0A 2C CA 22 EE F6 E6 37 F4 CA BE 5C 51 DE D2 E3 FA D8 B9 52 70 A3 21 84 56 64 F1 07 D1 64 96 BB 7A BF BE 75 04 B6 ED E2 E8 9E 4B 99 6F B5 8E FD C4 18 1F 91 63 38 1C BE 7B C0 06 A7 A2 05 98 9C 52 6C D1 BD 68 98 36 93 B4 BD C5 37 28 B2 41 C1 CF F4 2B B6 11 50 2C 35 20 5C AB B2 88 75 56 55 D6 20 C6 79 94 F0 64 51 18 7F 6F D1 7E 04 66 82 BA 12 86 06 3F F8 8F E2 50 8D 1F CA F9 03 5A 12 31 AD 41 50 A9 C9 B2 4C 9B 2D 66 B2 AD 1B DE 0B D0 BB CB 8B E0 5B 83 52 29 EF 79 19 73 73 23 42 44 01 E1 D8 37 B6 6E B4 E6 30 FF 1D E7 0C B3 17 C2 BA CB 08 00 1D 34 77 B7 A7 0A 57 6D 20 86 90 33 58 9D 85 A0 1D DB 2B 66 46 C0 43 B5 9F C0 11 31 1D A6 66 FA 5A D1 D6 38 7F A9 BC 40 15 A3 8A 51 D1 DA 1E A6 1D 64 8D C8 E3 9A 88 B9 D6 22 BD E2 07 FD AB C6 F2 82 7A 88 0C 33 0B BF 6D F7 33 77 4B 65 3E 57 30 5D 78 DC E1 12 F1 0A 2C 71 F4 CD AD 92 ED 11 3E 1C EA 63 B9 19 25 ED 28 19 1E 6D BB B5 AA 5A 2A FD A5 1F C0 5A 3A F5 25 8B 87 66 52 43 55 0F 28 94 8A E2 B8 BE B6 BC 9C 77 0B 35 F0 67 EA A6 41 EF E6 5B 1A 44 90 9D 1B 14 9F 97 EE A6 01 39 1C 60 9E C8 1D 19 30 F5 7C 18 A4 E0 FA B4 91 D1 CA DF D5 04 83 44 9E DC 0F 07 FF B2 4D 2C 6F 9A 9A 3B FF 39 AE 3D 57 F5 60 65 4D 7D 75 C9 08 AB E6 25 64 75 3E AC 39 D7 50 3D A6 D3 7C 2E 32 E1 AF 3B 8A EC 8A E3 06 9C D9";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHAKE128::hashAsHex(input_bits, digest_length);
    printf("digest size : %ld \n", expected_result.size() * 4);

    EXPECT_EQ(expected_result.substr(0, digest_length / 4), hex_result);
}

TEST(SHA3_Tests, SHAKE256_5_bit_input_4096bits) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg5.pdf
    
    std:vector<bool> input_bits = {true, true, false, false, true};
    int digest_length = 4096;

    std::string expected_result = "48 A5 C1 1A BA EE FF 09 2F 36 46 EF 0D 6B 3D 3F F7 6C 2F 55 F9 C7 32 AC 64 70 C0 37 64 00 82 12 E2 1B 14 67 77 8B 18 19 89 F8 88 58 21 1B 45 DF 87 99 CF 96 1F 80 0D FA C9 9E 64 40 39 E2 97 9A 40 16 F5 45 6F F4 21 C5 B3 85 DA 2B 85 5D A7 E3 1C 8C 2E 8E 4B A4 1E B4 09 5C B9 99 D9 75 9C B4 03 58 DA 85 62 A2 E6 13 49 E0 5A 2E 13 F1 B7 4E C9 E6 9F 5B 42 6D C7 41 38 FF CD C5 71 C3 2B 39 B9 F5 55 63 E1 A9 9D C4 22 C3 06 02 6D 6A 0F 9D E8 51 62 B3 86 79 4C A0 68 8B 76 4B 3D 32 20 0C C4 59 74 97 32 A0 F3 A3 41 C0 EF C9 6A 22 C6 3B AD 7D 96 CC 9B A4 76 8C 6F CF A1 F2 00 10 7C F9 FA E5 C0 D7 54 95 8C 5A 75 6B 37 6A 3B E6 9F 88 07 4F 20 0E 9E 95 A8 CA 5B CF 96 99 98 DB 1D C3 7D 0D 3D 91 6F 6C AA B3 F0 37 82 C9 C4 4A 2E 14 E8 07 86 BE CE 45 87 B9 EF 82 CB F4 54 E0 E3 4B D1 75 AE 57 D3 6A F4 E7 26 B2 21 33 2C ED 36 C8 CE 2E 06 20 3C 65 6A E8 DA 03 7D 08 E7 16 0B 48 0C 1A 85 16 BF 06 DD 97 BF 4A A4 C0 24 93 10 DC 0B 06 5D C6 39 57 63 55 38 4D 16 5C 6A 50 9B 12 F7 BB D1 E1 5B 22 BC E0 2F A0 48 DD FA AC F7 41 5F 49 B6 32 4C 1D 06 7B 52 64 E1 12 5F 7F 75 42 7F 31 2B D9 34 6E B4 E4 00 B1 F7 CB 31 28 8C 9E 3F 73 5E CA 9C ED 0D B8 88 E2 E2 F4 02 24 3B D6 46 18 A2 3E 10 F9 C2 29 39 74 40 54 2D 0A B1 B2 E1 0D AC C5 C9 5E 59 7F 2C 7E A3 84 38 10 5F 97 80 3D BB 03 FC C0 FD 41 6B 09 05 A4 1D 18 4D EB 23 89 05 77 58 91 F9 35 01 FB 41 76 A3 BD 6C 46 44 61 D3 6E E8 B0 08 AA BD 9E 26 A3 40 55 E8 0C 8C 81 3E EB A0 7F 72 8A B3 2B 15 60 5A D1 61 A0 66 9F 6F CE 5C 55 09 FB B6 AF D2 4A EA CC 5F A4 A5 15 23 E6 B1 73 24 6E D4 BF A5 21 D7 4F C6 BB";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHAKE256::hashAsHex(input_bits, digest_length);
    printf("digest size : %ld \n", expected_result.size() * 4);
    EXPECT_EQ(expected_result, hex_result);
}

TEST(SHA3_Tests, SHAKE256_5_bit_input_2048bits) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg5.pdf
    
    std:vector<bool> input_bits = {true, true, false, false, true};
    int digest_length = 2048;

    std::string expected_result = "48 A5 C1 1A BA EE FF 09 2F 36 46 EF 0D 6B 3D 3F F7 6C 2F 55 F9 C7 32 AC 64 70 C0 37 64 00 82 12 E2 1B 14 67 77 8B 18 19 89 F8 88 58 21 1B 45 DF 87 99 CF 96 1F 80 0D FA C9 9E 64 40 39 E2 97 9A 40 16 F5 45 6F F4 21 C5 B3 85 DA 2B 85 5D A7 E3 1C 8C 2E 8E 4B A4 1E B4 09 5C B9 99 D9 75 9C B4 03 58 DA 85 62 A2 E6 13 49 E0 5A 2E 13 F1 B7 4E C9 E6 9F 5B 42 6D C7 41 38 FF CD C5 71 C3 2B 39 B9 F5 55 63 E1 A9 9D C4 22 C3 06 02 6D 6A 0F 9D E8 51 62 B3 86 79 4C A0 68 8B 76 4B 3D 32 20 0C C4 59 74 97 32 A0 F3 A3 41 C0 EF C9 6A 22 C6 3B AD 7D 96 CC 9B A4 76 8C 6F CF A1 F2 00 10 7C F9 FA E5 C0 D7 54 95 8C 5A 75 6B 37 6A 3B E6 9F 88 07 4F 20 0E 9E 95 A8 CA 5B CF 96 99 98 DB 1D C3 7D 0D 3D 91 6F 6C AA B3 F0 37 82 C9 C4 4A 2E 14 E8 07 86 BE CE 45 87 B9 EF 82 CB F4 54 E0 E3 4B D1 75 AE 57 D3 6A F4 E7 26 B2 21 33 2C ED 36 C8 CE 2E 06 20 3C 65 6A E8 DA 03 7D 08 E7 16 0B 48 0C 1A 85 16 BF 06 DD 97 BF 4A A4 C0 24 93 10 DC 0B 06 5D C6 39 57 63 55 38 4D 16 5C 6A 50 9B 12 F7 BB D1 E1 5B 22 BC E0 2F A0 48 DD FA AC F7 41 5F 49 B6 32 4C 1D 06 7B 52 64 E1 12 5F 7F 75 42 7F 31 2B D9 34 6E B4 E4 00 B1 F7 CB 31 28 8C 9E 3F 73 5E CA 9C ED 0D B8 88 E2 E2 F4 02 24 3B D6 46 18 A2 3E 10 F9 C2 29 39 74 40 54 2D 0A B1 B2 E1 0D AC C5 C9 5E 59 7F 2C 7E A3 84 38 10 5F 97 80 3D BB 03 FC C0 FD 41 6B 09 05 A4 1D 18 4D EB 23 89 05 77 58 91 F9 35 01 FB 41 76 A3 BD 6C 46 44 61 D3 6E E8 B0 08 AA BD 9E 26 A3 40 55 E8 0C 8C 81 3E EB A0 7F 72 8A B3 2B 15 60 5A D1 61 A0 66 9F 6F CE 5C 55 09 FB B6 AF D2 4A EA CC 5F A4 A5 15 23 E6 B1 73 24 6E D4 BF A5 21 D7 4F C6 BB";
    expected_result.erase(std::remove(expected_result.begin(), expected_result.end(), ' '), expected_result.end());

    std::string hex_result = SHAKE256::hashAsHex(input_bits, digest_length);
    printf("digest size : %ld \n", expected_result.size() * 4);

    EXPECT_EQ(expected_result.substr(0, digest_length / 4), hex_result);
}