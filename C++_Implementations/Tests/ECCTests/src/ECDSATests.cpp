#include <gtest/gtest.h>  
#include <stddef.h>

#include "ECDSA.hpp"

TEST(ECC_Tests, ECDSA_secp224r1SignatureGeneration) {
    printf("running test");
    ECDSA ecdsa = ECDSA(EllipticCurves::SECP224R1_);
    printf("running test");
    std::string message_string = "Example of ECDSA with P-224";
    std::string expected_r = "C3A3F5B82712532004C6F6D1DB672F55D931C3409EA1216D0BE77380";
    std::string expected_s = "485732290B465E864A3345FF12673303FEAA4DB68AC29D784BF6DAE2";
    ECDSA_Signature expected = ECDSA_Signature(expected_r, expected_s);
    std::string d_hex = "3F0C488E987C80BE0FEE521F8D90BE6034EC69AE11CA72AA777481E8";
    ECDSA_Signature signature = ecdsa.SignatureGeneration(message_string, d_hex);

    EXPECT_EQ(expected, signature);
}