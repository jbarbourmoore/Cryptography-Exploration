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

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
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

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}


/// This method tests AES GCM with a several block plain text length
/// Test Case 3 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test003_aes128_severalblockpt){
    std::string key = "feffe9928665731c6d6a8f9467308308";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_128;
    std::string initialization_vector = "cafebabefacedbaddecaf888";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255";
    std::string expected_tag = "4D5C2AF327CD64A62CF35ABD2BA6FAB4";
    std::string expected_cypher = "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091473F5985";
    int tag_length = 32;
    std::string additional_data = "";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);
    
    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a partial block length of plain text
/// Test Case 4 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test004_aes128_partialblockpt){
    std::string key = "feffe9928665731c6d6a8f9467308308";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_128;
    std::string initialization_vector = "cafebabefacedbaddecaf888";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39";
    std::string expected_tag = "5BC94FBC3221A5DB94FAE95AE7121A47";
    std::string expected_cypher = "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091";
    int tag_length = 32;
    std::string additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a short initialization vector
/// Test Case 5 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test005_aes128_shortiv){
    std::string key = "feffe9928665731c6d6a8f9467308308";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_128;
    std::string initialization_vector = "cafebabefacedbad";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39";
    std::string expected_tag = "3612D2E79E3B0785561BE14AACA2FCCB";
    std::string expected_cypher = "61353B4C2806934A777FF51FA22A4755699B2A714FCDC6F83766E5F97B6C742373806900E49F24B22B097544D4896B424989B5E1EBAC0F07C23F4598";
    int tag_length = 32;
    std::string additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a long initialization vector
/// Test Case 6 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test006_aes128_longiv){
    std::string key = "feffe9928665731c6d6a8f9467308308";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_128;
    std::string initialization_vector = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39";
    std::string expected_tag = "619CC5AEFFFE0BFA462AF43C1699D050";
    std::string expected_cypher = "8CE24998625615B603A033ACA13FB894BE9112A5C3A211A8BA262A3CCA7E2CA701E4A9A4FBA43C90CCDCB281D48C7C6FD62875D2ACA417034C34AEE5";
    int tag_length = 32;
    std::string additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}


/// This method tests AES GCM with a 0 bit plain text length
/// Test Case 7 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test007_aes192_0bitpt){
    std::string key = "000000000000000000000000000000000000000000000000";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_192;
    std::string initialization_vector = "000000000000000000000000";
    std::string plain_text = "";
    std::string expected_tag = "CD33B28AC773F74BA00ED1F312572435";
    std::string expected_cypher = "";
    int tag_length = 32;
    std::string additional_data = "";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a 128 bit plain text length
/// Test Case 8 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test008_aes192_128bitpt){
    std::string key = "000000000000000000000000000000000000000000000000";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_192;
    std::string initialization_vector = "000000000000000000000000";
    std::string plain_text = "00000000000000000000000000000000";
    std::string expected_tag = "2FF58D80033927AB8EF4D4587514F0FB";
    std::string expected_cypher = "98E7247C07F0FE411C267E4384B0F600";
    int tag_length = 32;
    std::string additional_data = "";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);
    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}


/// This method tests AES GCM with a several block plain text length
/// Test Case 9 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test009_aes192_severalblockpt){
    std::string key = "feffe9928665731c6d6a8f9467308308feffe9928665731c";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_192;
    std::string initialization_vector = "cafebabefacedbaddecaf888";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255";
    std::string expected_tag = "9924A7C8587336BFB118024DB8674A14";
    std::string expected_cypher = "3980CA0B3C00E841EB06FAC4872A2757859E1CEAA6EFD984628593B40CA1E19C7D773D00C144C525AC619D18C84A3F4718E2448B2FE324D9CCDA2710ACADE256";
    int tag_length = 32;
    std::string additional_data = "";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);
    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a partial block length of plain text
/// Test Case 10 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test010_aes192_partialblockpt){
    std::string key = "feffe9928665731c6d6a8f9467308308feffe9928665731c";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_192;
    std::string initialization_vector = "cafebabefacedbaddecaf888";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39";
    std::string expected_tag = "2519498E80F1478F37BA55BD6D27618C";
    std::string expected_cypher = "3980CA0B3C00E841EB06FAC4872A2757859E1CEAA6EFD984628593B40CA1E19C7D773D00C144C525AC619D18C84A3F4718E2448B2FE324D9CCDA2710";
    int tag_length = 32;
    std::string additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);
    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a short initialization vector
/// Test Case 11 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test011_aes192_shortiv){
    std::string key = "feffe9928665731c6d6a8f9467308308feffe9928665731c";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_192;
    std::string initialization_vector = "cafebabefacedbad";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39";
    std::string expected_tag = "65DCC57FCF623A24094FCCA40D3533F8";
    std::string expected_cypher = "0F10F599AE14A154ED24B36E25324DB8C566632EF2BBB34F8347280FC4507057FDDC29DF9A471F75C66541D4D4DAD1C9E93A19A58E8B473FA0F062F7";
    int tag_length = 32;
    std::string additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);
    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a long initialization vector
/// Test Case 12 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test012_aes192_longiv){
    std::string key = "feffe9928665731c6d6a8f9467308308feffe9928665731c";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_192;
    std::string initialization_vector = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39";
    std::string expected_tag = "DCF566FF291C25BBB8568FC3D376A6D9";
    std::string expected_cypher = "D27E88681CE3243C4830165A8FDCF9FF1DE9A1D8E6B447EF6EF7B79828666E4581E79012AF34DDD9E2F037589B292DB3E67C036745FA22E7E9B7373B";
    int tag_length = 32;
    std::string additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);
    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a 0 bit plain text length
/// Test Case 13 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test013_aes256_0bitpt){
    std::string key = "0000000000000000000000000000000000000000000000000000000000000000";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_256;
    std::string initialization_vector = "000000000000000000000000";
    std::string plain_text = "";
    std::string expected_tag = "530F8AFBC74536B9A963B4F1C4CB738B";
    std::string expected_cypher = "";
    int tag_length = 32;
    std::string additional_data = "";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);
    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a 128 bit plain text length
/// Test Case 14 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test014_aes256_128bitpt){
    std::string key = "0000000000000000000000000000000000000000000000000000000000000000";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_256;
    std::string initialization_vector = "000000000000000000000000";
    std::string plain_text = "00000000000000000000000000000000";
    std::string expected_tag = "D0D1C8A799996BF0265B98B5D48AB919";
    std::string expected_cypher = "CEA7403D4D606B6E074EC5D3BAF39D18";
    int tag_length = 32;
    std::string additional_data = "";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a several block plain text length
/// Test Case 15 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test015_aes256_severalblockpt){
    std::string key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_256;
    std::string initialization_vector = "cafebabefacedbaddecaf888";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255";
    std::string expected_tag = "B094DAC5D93471BDEC1A502270E3CC6C";
    std::string expected_cypher = "522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662898015AD";
    int tag_length = 32;
    std::string additional_data = "";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);
    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);
    
    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a partial block length of plain text
/// Test Case 16 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test016_aes256_partialblockpt){
    std::string key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_256;
    std::string initialization_vector = "cafebabefacedbaddecaf888";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39";
    std::string expected_tag = "76FC6ECE0F4E1768CDDF8853BB2D551B";
    std::string expected_cypher = "522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662";
    int tag_length = 32;
    std::string additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a short initialization vector
/// Test Case 17 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test017_aes256_shortiv){
    std::string key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_256;
    std::string initialization_vector = "cafebabefacedbad";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39";
    std::string expected_tag = "3A337DBF46A792C45E454913FE2EA8F2";
    std::string expected_cypher = "C3762DF1CA787D32AE47C13BF19844CBAF1AE14D0B976AFAC52FF7D79BBA9DE0FEB582D33934A4F0954CC2363BC73F7862AC430E64ABE499F47C9B1F";
    int tag_length = 32;
    std::string additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

/// This method tests AES GCM with a long initialization vector
/// Test Case 18 from "The Galois/Counter Mode of Operation (GCM)" : Appendix B "AES Test Vectors"
/// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
TEST(AES_GCM_Tests, test018_aes256_longiv){
    std::string key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    AESKeyTypes key_type = AESKeyTypes::AES_KEY_256;
    std::string initialization_vector = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b";
    std::string plain_text = "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39";
    std::string expected_tag = "A44A8266EE1C8EB0C8B5D4CF5AE9F19A";
    std::string expected_cypher = "5A8DEF2F0C9E53F1F75D7853659E2A20EEB2B22AAFDE6419A058AB4F6F746BF40FC0C3B780F244452DA3EBF1C5D82CDEA2418997200EF82E44AE7E3F";
    int tag_length = 32;
    std::string additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    GCM_EncyptionResult result = AES_GCM::authenticatedEncryption(plain_text, key_type, key, tag_length, initialization_vector, additional_data);

    EXPECT_EQ(result.cipher_text_, expected_cypher);
    EXPECT_EQ(result.tag_, expected_tag);

    GCM_DecryptionResult decrypt_result = AES_GCM::authenticatedDecryption(result.cipher_text_, key_type, key, result.tag_, tag_length, initialization_vector, additional_data);
    EXPECT_TRUE(decrypt_result.status_);
    EXPECT_EQ(decrypt_result.plain_text_, plain_text);
}

