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

    Point Q = Point("E84FB0B8E7000CB657D7973CF6B42ED78B301674276DF744AF130B3E", "4376675C6FC5612C21A0FF2D2A89D2987DF7A2BC52183B5982298555");
    bool verified = ecdsa.SignatureVerification(message_string, Q, signature);
    EXPECT_TRUE(verified);

    Point not_Q = Point("E84FB0B8E7000CB657D7973CF6B42ED78B301674276DF744AF130B3A", "4376675C6FC5612C21A0FF2D2A89D2987DF7A2BC52183B5982298555");
    bool not_verified = ecdsa.SignatureVerification(message_string, not_Q, signature);
    EXPECT_FALSE(not_verified);
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

    Point Q = Point("B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19", "3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09");
    bool verified = ecdsa.SignatureVerification(message_string, Q, signature);
    EXPECT_TRUE(verified);

    Point not_Q = Point("B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19", "3603F747959DBF7A4BB226E41928719063ADC7AE43529E61B563BBC606CC5E09");
    bool not_verified = ecdsa.SignatureVerification(message_string, not_Q, signature);
    EXPECT_FALSE(not_verified);
}

//test values from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P384_SHA384.pdf 
TEST(ECC_Tests, ECDSA_secp384r1SignatureGeneration) {
    ECDSA ecdsa = ECDSA(EllipticCurves::SECP384R1_);
    std::string message_string = "Example of ECDSA with P-384";
    std::string given_k_hex = "2E44EF1F8C0BEA8394E3DDA81EC6A7842A459B534701749E2ED95F054F0137680878E0749FC43F85EDCAE06CC2F43FEF";
    std::string expected_r = "30EA514FC0D38D8208756F068113C7CADA9F66A3B40EA3B313D040D9B57DD41A332795D02CC7D507FCEF9FAF01A27088";
    std::string expected_s = "CC808E504BE414F46C9027BCBF78ADF067A43922D6FCAA66C4476875FBB7B94EFD1F7D5DBE620BFB821C46D549683AD8";
    ECDSA_Signature expected = ECDSA_Signature(expected_r, expected_s);
    std::string d_hex = "F92C02ED629E4B48C0584B1C6CE3A3E3B4FAAE4AFC6ACB0455E73DFC392E6A0AE393A8565E6B9714D1224B57D83F8A08";
    ECDSA_Signature signature = ecdsa.SignatureGeneration(message_string, d_hex, given_k_hex);
    signature.print();
    EXPECT_EQ(expected, signature);

    Point Q = Point("3BF701BC9E9D36B4D5F1455343F09126F2564390F2B487365071243C61E6471FB9D2AB74657B82F9086489D9EF0F5CB5", "D1A358EAFBF952E68D533855CCBDAA6FF75B137A5101443199325583552A6295FFE5382D00CFCDA30344A9B5B68DB855");
    bool verified = ecdsa.SignatureVerification(message_string, Q, signature);
    EXPECT_TRUE(verified);

    Point not_Q = Point("1BF701BC9E9D36B4D5F1455343F09126F2564390F2B487365071243C61E6471FB9D2AB74657B82F9086489D9EF0F5CB5", "D1A358EAFBF952E68D533855CCBDAA6FF75B137A5101443199325583552A6295FFE5382D00CFCDA30344A9B5B68DB855");
    bool not_verified = ecdsa.SignatureVerification(message_string, not_Q, signature);
    EXPECT_FALSE(not_verified);
}

//test values from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA512.pdf 
TEST(ECC_Tests, ECDSA_secp521r1SignatureGeneration) {
    ECDSA ecdsa = ECDSA(EllipticCurves::SECP521R1_);
    std::string message_string = "Example of ECDSA with P-521";
    std::string given_k_hex = "C91E2349EF6CA22D2DE39DD51819B6AAD922D3AECDEAB452BA172F7D63E370CECD70575F597C09A174BA76BED05A48E562BE0625336D16B8703147A6A231D6BF";
    std::string expected_r = "140C8EDCA57108CE3F7E7A240DDD3AD74D81E2DE62451FC1D558FDC79269ADACD1C2526EEEEF32F8C0432A9D56E2B4A8A732891C37C9B96641A9254CCFE5DC3E2BA";
    std::string expected_s = "D72F15229D0096376DA6651D9985BFD7C07F8D49583B545DB3EAB20E0A2C1E8615BD9E298455BDEB6B61378E77AF1C54EEE2CE37B2C61F5C9A8232951CB988B5B1";
    ECDSA_Signature expected = ECDSA_Signature(expected_r, expected_s);
    std::string d_hex = "100085F47B8E1B8B11B7EB33028C0B2888E304BFC98501955B45BBA1478DC184EEEDF09B86A5F7C21994406072787205E69A63709FE35AA93BA333514B24F961722";
    ECDSA_Signature signature = ecdsa.SignatureGeneration(message_string, d_hex, given_k_hex);
    signature.print();
    EXPECT_EQ(expected, signature);

    Point Q = Point("98E91EEF9A68452822309C52FAB453F5F117C1DA8ED796B255E9AB8F6410CCA16E59DF403A6BDC6CA467A37056B1E54B3005D8AC030DECFEB68DF18B171885D5C4", "164350C321AECFC1CCA1BA4364C9B15656150B4B78D6A48D7D28E7F31985EF17BE8554376B72900712C4B83AD668327231526E313F5F092999A4632FD50D946BC2E");
    bool verified = ecdsa.SignatureVerification(message_string, Q, signature);
    EXPECT_TRUE(verified);

    Point not_Q = Point("98E91EEF9A68452822309C52FAB453F5F117C1DA8ED796B255E9AB8F6410CCA16E59DF403A6BDC6CA467A37056B1E54B3005D8AC030DECFEB68DF18B171885D5C4", "164350C321AECFC1CCA1BA4364C9B15656150B4B78D6A48D7D28E7F31985EF17BE8554376B72900712C4B83AD668327231526E313F5F092999A4632FD50D946BC2D");
    bool not_verified = ecdsa.SignatureVerification(message_string, not_Q, signature);
    EXPECT_FALSE(not_verified);
}