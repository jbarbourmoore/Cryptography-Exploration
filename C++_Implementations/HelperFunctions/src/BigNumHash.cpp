/// This file is a helper function for hashing openSSL BIGNUM
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
///                 OpenSSL EVP for handling the actual hashing
/// Author        : Jamie Barbour-Moore
/// Created       : 05/13/25
/// Updated       : 05/13/25

#include "BigNumHelpers.hpp"
#include "CreateHashDigest.hpp"

void BigNumHelpers::sha224BigNum(BIGNUM* result, BIGNUM* input_bn){
    char *hex_to_hash = BN_bn2hex(input_bn);
    std::string str = std::string(hex_to_hash);

    std::string hex_result = CreateHashDigest::fromHexString(str, HashType::SHA224_DIGEST);
    BN_hex2bn(&result, hex_result.c_str());

    OPENSSL_free(hex_to_hash);
};

void BigNumHelpers::sha256BigNum(BIGNUM* result, BIGNUM* input_bn){
    char *hex_to_hash = BN_bn2hex(input_bn);
    std::string str = std::string(hex_to_hash);

    std::string hex_result = CreateHashDigest::fromHexString(str, HashType::SHA256_DIGEST);
    BN_hex2bn(&result, hex_result.c_str());

    OPENSSL_free(hex_to_hash);
};

void BigNumHelpers::sha384BigNum(BIGNUM* result, BIGNUM* input_bn){
    char *hex_to_hash = BN_bn2hex(input_bn);
    std::string str = std::string(hex_to_hash);

    std::string hex_result = CreateHashDigest::fromHexString(str, HashType::SHA384_DIGEST);
    BN_hex2bn(&result, hex_result.c_str());

    OPENSSL_free(hex_to_hash);
};

void BigNumHelpers::sha512BigNum(BIGNUM* result, BIGNUM* input_bn){
    char *hex_to_hash = BN_bn2hex(input_bn);
    std::string str = std::string(hex_to_hash);

    std::string hex_result = CreateHashDigest::fromHexString(str, HashType::SHA512_DIGEST);
    BN_hex2bn(&result, hex_result.c_str());

    OPENSSL_free(hex_to_hash);
};