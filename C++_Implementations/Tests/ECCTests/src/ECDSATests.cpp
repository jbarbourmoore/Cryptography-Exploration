#include <gtest/gtest.h>  
#include <stddef.h>

#include "ECDSA.hpp"

// test values from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P224_SHA224.pdf 
TEST(ECC_Tests, ECDSA_secp224r1SignatureGeneration) {
    ECDSA ecdsa = ECDSA(EllipticCurves::SECP224R1_);
    std::string message_string = "Example of ECDSA with P-224";
    std::string given_k_hex = "A548803B79DF17C40CDE3FF0E36D025143BCBBA146EC32908EB84937";
    std::string expected_r = "C3A3F5B82712532004C6F6D1DB672F55D931C3409EA1216D0BE77380";
    std::string expected_s = "C5AA1EAE6095DEA34C9BD84DA3852CCA41A8BD9D5548F36DABDF6617";
    ECDSA_Signature expected = ECDSA_Signature(expected_r, expected_s);
    std::string d_hex = "3F0C488E987C80BE0FEE521F8D90BE6034EC69AE11CA72AA777481E8";
    ECDSA_Signature signature = ecdsa.SignatureGeneration(message_string, d_hex, given_k_hex);
    signature.print();
    EXPECT_EQ(expected, signature);
}