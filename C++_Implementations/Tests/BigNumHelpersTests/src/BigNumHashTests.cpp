#include <gtest/gtest.h>  
#include <stddef.h>

#include "BigNumHelpers.hpp"

TEST(BigNumHash_Tests, sha224_bn) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA224.pdf
    
    const char *hex_str = "616263";
    const char *expected = "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7";
    BIGNUM *to_hash = BN_new();
    BIGNUM *result_bn = BN_new();

    BN_hex2bn(&to_hash, hex_str);
    
    BigNumHelpers::sha224BigNum(result_bn, to_hash);

    char* result_hex = BN_bn2hex(result_bn);

    printf("Testing the SHA224 hash of %s\n", hex_str);
    printf("Expected Output : %s\n", expected);
    printf("Actual Output   : %s\n", result_hex);

    EXPECT_EQ(strcmp(expected, result_hex), 0);

    OPENSSL_free(result_hex);
    BN_free(to_hash);
    BN_free(result_bn);
}

TEST(BigNumHash_Tests, sha256_bn) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
    
    const char *hex_str = "616263";
    const char *expected = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
    BIGNUM *to_hash = BN_new();
    BIGNUM *result_bn = BN_new();

    BN_hex2bn(&to_hash, hex_str);
    
    BigNumHelpers::sha256BigNum(result_bn, to_hash);

    char* result_hex = BN_bn2hex(result_bn);

    printf("Testing the SHA256 hash of %s\n", hex_str);
    printf("Expected Output : %s\n", expected);
    printf("Actual Output   : %s\n", result_hex);

    EXPECT_EQ(strcmp(expected, result_hex), 0);

    OPENSSL_free(result_hex);
    BN_free(to_hash);
    BN_free(result_bn);
}

TEST(BigNumHash_Tests, sha384_bn) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf
    
    const char *hex_str = "616263";
    const char *expected = "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7";
    BIGNUM *to_hash = BN_new();
    BIGNUM *result_bn = BN_new();

    BN_hex2bn(&to_hash, hex_str);
    
    BigNumHelpers::sha384BigNum(result_bn, to_hash);

    char* result_hex = BN_bn2hex(result_bn);

    printf("Testing the SHA384 hash of %s\n", hex_str);
    printf("Expected Output : %s\n", expected);
    printf("Actual Output   : %s\n", result_hex);

    EXPECT_EQ(strcmp(expected, result_hex), 0);

    OPENSSL_free(result_hex);
    BN_free(to_hash);
    BN_free(result_bn);
}
TEST(BigNumHash_Tests, sha512_bn) {
    // test values taken from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
    
    const char *hex_str = "616263";
    const char *expected = "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F";
    BIGNUM *to_hash = BN_new();
    BIGNUM *result_bn = BN_new();

    BN_hex2bn(&to_hash, hex_str);
    
    BigNumHelpers::sha512BigNum(result_bn, to_hash);

    char* result_hex = BN_bn2hex(result_bn);

    printf("Testing the SHA512 hash of %s\n", hex_str);
    printf("Expected Output : %s\n", expected);
    printf("Actual Output   : %s\n", result_hex);

    EXPECT_EQ(strcmp(expected, result_hex), 0);

    OPENSSL_free(result_hex);
    BN_free(to_hash);
    BN_free(result_bn);
}