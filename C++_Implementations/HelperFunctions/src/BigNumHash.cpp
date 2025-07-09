/// This file is a helper function for hashing openSSL BIGNUM
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
///                 OpenSSL EVP for handling the actual hashing
/// Author        : Jamie Barbour-Moore
/// Created       : 05/13/25
/// Updated       : 05/13/25

#include "BigNumHelpers.hpp"
#include "CreateHashDigest.hpp"
#include "SHA3.hpp"

void BigNumHelpers::sha3_224BigNum(BIGNUM* result, BIGNUM* input_bn){
    char *hex_to_hash = BN_bn2hex(input_bn);
    std::string str = std::string(hex_to_hash);

    std::string hex_result = SHA3_224::hashAsHex(str);
    BN_hex2bn(&result, hex_result.c_str());

    OPENSSL_free(hex_to_hash);
};

void BigNumHelpers::sha3_256BigNum(BIGNUM* result, BIGNUM* input_bn){
    char *hex_to_hash = BN_bn2hex(input_bn);
    std::string str = std::string(hex_to_hash);

    std::string hex_result = SHA3_256::hashAsHex(str);
    BN_hex2bn(&result, hex_result.c_str());

    OPENSSL_free(hex_to_hash);
};

void BigNumHelpers::sha3_384BigNum(BIGNUM* result, BIGNUM* input_bn){
    char *hex_to_hash = BN_bn2hex(input_bn);
    std::string str = std::string(hex_to_hash);

    std::string hex_result = SHA3_384::hashAsHex(str);
    BN_hex2bn(&result, hex_result.c_str());

    OPENSSL_free(hex_to_hash);
};

void BigNumHelpers::sha3_512BigNum(BIGNUM* result, BIGNUM* input_bn){
    char *hex_to_hash = BN_bn2hex(input_bn);
    std::string str = std::string(hex_to_hash);

    std::string hex_result = SHA3_512::hashAsHex(str);
    BN_hex2bn(&result, hex_result.c_str());

    OPENSSL_free(hex_to_hash);
};

void BigNumHelpers::shake128BigNum(BIGNUM* result, BIGNUM* input_bn, int digest_length){
    char *hex_to_hash = BN_bn2hex(input_bn);
    std::string str = std::string(hex_to_hash);

    std::string hex_result = SHAKE128::hashAsHex(str, digest_length);
    BN_hex2bn(&result, hex_result.c_str());

    OPENSSL_free(hex_to_hash);
}

void BigNumHelpers::shake256BigNum(BIGNUM* result, BIGNUM* input_bn, int digest_length){
    char *hex_to_hash = BN_bn2hex(input_bn);
    std::string str = std::string(hex_to_hash);

    std::string hex_result = SHAKE256::hashAsHex(str, digest_length);
    BN_hex2bn(&result, hex_result.c_str());

    OPENSSL_free(hex_to_hash);
}

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