#include <gtest/gtest.h>  
#include <stddef.h>

#include "BigNumHelpers.hpp"

/// @brief This unit tests using xor on two inputed big numbers
TEST(BigNumXOR_Tests, XORBigNumber_FF_AA) {

    const char *first_str = "FF";
    const char *second_str = "AA";
    const char *expected_str = "55";

    BN_CTX *test_ctx = BN_CTX_new();
    BN_CTX_start(test_ctx);

    BIGNUM *result = BN_CTX_get(test_ctx);
    BIGNUM *first_value = BN_CTX_get(test_ctx);
    BIGNUM *second_value = BN_CTX_get(test_ctx);

    BN_hex2bn(&first_value, first_str);
    BN_hex2bn(&second_value, second_str);

    BigNumHelpers::xorBigNums(result, first_value, second_value);
    
    char *result_str = BN_bn2hex(result);
    printf("Testing the XOR of %s and %s\n", first_str, second_str);
    printf("Expected Output : %s\n", expected_str);
    printf("Actual Output   : %s\n", result_str);
    EXPECT_EQ(strcmp(expected_str, result_str), 0);

    OPENSSL_free(result_str);
    BN_CTX_end(test_ctx);
    BN_CTX_free(test_ctx);
}

/// @brief This unit tests using xor on two inputed big numbers
TEST(BigNumXOR_Tests, XORBigNumber_FAB2381724_ABF123A) {

    const char *first_str = "FAB2381724";
    const char *second_str = "ABF123A";
    const char *expected_str = "FAB887051E";

    BN_CTX *test_ctx = BN_CTX_new();
    BN_CTX_start(test_ctx);

    BIGNUM *result = BN_CTX_get(test_ctx);
    BIGNUM *first_value = BN_CTX_get(test_ctx);
    BIGNUM *second_value = BN_CTX_get(test_ctx);

    BN_hex2bn(&first_value, first_str);
    BN_hex2bn(&second_value, second_str);

    BigNumHelpers::xorBigNums(result, first_value, second_value);
    
    char *result_str = BN_bn2hex(result);
    printf("Testing the XOR of %s and %s\n", first_str, second_str);
    printf("Expected Output : %s\n", expected_str);
    printf("Actual Output   : %s\n", result_str);
    EXPECT_EQ(strcmp(expected_str, result_str), 0);

    OPENSSL_free(result_str);
    BN_CTX_end(test_ctx);
    BN_CTX_free(test_ctx);
}

/// @brief This unit tests using xor on two inputed big numbers
TEST(BigNumXOR_Tests, XORBigNumber_FFFFFFFFFFFFFFF_FFFFFFFFFFFFFFF) {

    const char *first_str = "FFFFFFFFFFFFFFF";
    const char *second_str = "FFFFFFFFFFFFFFF";
    const char *expected_str = "0";

    BN_CTX *test_ctx = BN_CTX_new();
    BN_CTX_start(test_ctx);

    BIGNUM *result = BN_CTX_get(test_ctx);
    BIGNUM *first_value = BN_CTX_get(test_ctx);
    BIGNUM *second_value = BN_CTX_get(test_ctx);

    BN_hex2bn(&first_value, first_str);
    BN_hex2bn(&second_value, second_str);

    BigNumHelpers::xorBigNums(result, first_value, second_value);
    
    char *result_str = BN_bn2hex(result);
    printf("Testing the XOR of %s and %s\n", first_str, second_str);
    printf("Expected Output : %s\n", expected_str);
    printf("Actual Output   : %s\n", result_str);
    EXPECT_EQ(strcmp(expected_str, result_str), 0);

    OPENSSL_free(result_str);
    BN_CTX_end(test_ctx);
    BN_CTX_free(test_ctx);
}

/// @brief This unit tests using xor on two inputed big numbers
TEST(BigNumXOR_Tests, XORBigNumber_2222_8888) {

    const char *first_str = "22222222222222222222";
    const char *second_str = "88888888888888888888";
    const char *expected_str = "AAAAAAAAAAAAAAAAAAAA";

    BN_CTX *test_ctx = BN_CTX_new();
    BN_CTX_start(test_ctx);

    BIGNUM *result = BN_CTX_get(test_ctx);
    BIGNUM *first_value = BN_CTX_get(test_ctx);
    BIGNUM *second_value = BN_CTX_get(test_ctx);

    BN_hex2bn(&first_value, first_str);
    BN_hex2bn(&second_value, second_str);

    BigNumHelpers::xorBigNums(result, first_value, second_value);
    
    char *result_str = BN_bn2hex(result);
    printf("Testing the XOR of %s and %s\n", first_str, second_str);
    printf("Expected Output : %s\n", expected_str);
    printf("Actual Output   : %s\n", result_str);
    EXPECT_EQ(strcmp(expected_str, result_str), 0);

    OPENSSL_free(result_str);
    BN_CTX_end(test_ctx);
    BN_CTX_free(test_ctx);
}