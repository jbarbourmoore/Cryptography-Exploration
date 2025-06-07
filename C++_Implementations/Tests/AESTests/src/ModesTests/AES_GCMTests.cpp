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

/// This method tests AES GCM with a 0 bit plain text length
/// Test Case 1 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test001_aes128_0bitpt){
    std::string key = "00000000000000000000000000000000";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_128;
    std::string initialization_vector = "000000000000000000000000";
    std::string plain_text = "";
    std::string expected_tag = "58E2FCCEFA7E3061367F1D57A4E7455A";
    std::string expected_cypher = "";
    int tag_length = 32;
    std::string additional_data = "";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);
}

/// This method tests AES GCM with a 128 bit plain text length
/// Test Case 2 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test002_aes128_128bitpt){
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


/// This method tests AES GCM with a several block plain text length
/// Test Case 3 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test003_aes128_severalblockpt){
    std::string key = "feffe9928665731c6d6a8f9467308308";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_128;
    std::string initialization_vector = "cafebabefacedbaddecaf888";
    std::string plain_text = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
    std::string expected_tag = "4D5C2AF327CD64A62CF35ABD2BA6FAB4";
    std::string expected_cypher = "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091473F5985";
    int tag_length = 32;
    std::string additional_data = "";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);
}

/// This method tests AES GCM with a partial block length of plain text
/// Test Case 4 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test004_aes128_partialblockpt){
    std::string key = "feffe9928665731c6d6a8f9467308308";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_128;
    std::string initialization_vector = "cafebabefacedbaddecaf888";
    std::string plain_text = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
    std::string expected_tag = "5BC94FBC3221A5DB94FAE95AE7121A47";
    std::string expected_cypher = "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091";
    int tag_length = 32;
    std::string additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);
}