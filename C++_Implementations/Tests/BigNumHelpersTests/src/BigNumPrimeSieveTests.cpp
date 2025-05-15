#include <gtest/gtest.h>  
#include <stddef.h>

#include "BigNumHelpers.hpp"

/// @brief This unit tests using prime seive to find all primes under 20
TEST(PrimeSieve_Tests, PrimeSieveBigNumber_20) {
    int max = 20;
    BIGNUM *max_bn = BN_new();
    BN_set_word(max_bn, max);
    std::vector<unsigned long long int> expected_primes = {2, 3, 5, 7, 11, 13, 17, 19};
    std::vector<unsigned long long int> primes = BigNumHelpers::primeSieve(max_bn);

    for (int i = 0; i < primes.size(); i ++){
        printf("%lld, ",primes[i]);
    }

    EXPECT_EQ(primes, expected_primes);
}

/// @brief This unit tests using prime seive to find all primes under 50
TEST(PrimeSieve_Tests, PrimeSieveBigNumber_50) {
    int max = 50;
    BIGNUM *max_bn = BN_new();
    BN_set_word(max_bn, max);
    std::vector<unsigned long long int> expected_primes = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47};
    std::vector<unsigned long long int> primes = BigNumHelpers::primeSieve(max_bn);

    for (int i = 0; i < primes.size(); i ++){
        printf("%lld, ",primes[i]);
    }

    EXPECT_EQ(primes, expected_primes);
}