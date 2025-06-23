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

//test values from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P256_SHA256.pdf 
TEST(ECC_Tests, ECDSA_secp256r1SignatureGeneration) {
    ECDSA ecdsa = ECDSA(EllipticCurves::SECP256R1_);
    std::string message_string = "Example of ECDSA with P-256";
    std::string given_k_hex = "7A1A7E52797FC8CAAA435D2A4DACE39158504BF204FBE19F14DBB427FAEE50AE";
    std::string expected_r = "2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F";
    std::string expected_s = "DC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1";
    ECDSA_Signature expected = ECDSA_Signature(expected_r, expected_s);
    std::string d_hex = "C477F9F65C22CCE20657FAA5B2D1D8122336F851A508A1ED04E479C34985BF96";
    ECDSA_Signature signature = ecdsa.SignatureGeneration(message_string, d_hex, given_k_hex);
    signature.print();
    EXPECT_EQ(expected, signature);
}