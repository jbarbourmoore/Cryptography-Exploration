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

/// This method tests AES GCM with a 128 bit plain text length
/// Test Case 2 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, aes128_128bitpt_test){
    std::string key = "00000000000000000000000000000000";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_128;
    std::string initialization_vector = "000000000000000000000000";
    std::string plain_text = "00000000000000000000000000000000";
    std::string expected_tag = "AB6E47D42CEC13BDF53A67B21257BDDF";
    std::string expected_cypher = "0388DACE60B6A392F328C2B971B2FE78";
    int tag_length = 32;
    std::string additional_data = "";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);
}