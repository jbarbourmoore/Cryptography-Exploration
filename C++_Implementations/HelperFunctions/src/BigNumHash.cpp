/// This file is a helper function for hashing openSSL BIGNUM
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
///                 OpenSSL EVP for handling the actual hashing
/// Author        : Jamie Barbour-Moore
/// Created       : 05/13/25
/// Updated       : 05/13/25

#include "BigNumHelpers.hpp"
BIGNUM* BigNumHelpers::sha224BigNum(BIGNUM* bignum_to_hash){
    BIGNUM *hash_result = BN_new();
    unsigned hash_length_bytes = 224/8;

    // convert the bignum into a byte array to be hashed
    size_t size = BN_num_bytes(bignum_to_hash);
    unsigned char *byte_array_to_hash = new unsigned char[size]();
    BN_bn2bin(bignum_to_hash, byte_array_to_hash);

    // Initialize a digest and add the byte arrat to hash to it
    EVP_MD_CTX *hash_context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash_context, EVP_sha224(), NULL);
    EVP_DigestUpdate(hash_context, byte_array_to_hash, size);

    // extracted the hash digest as a byte array
    unsigned char hash_result_bytes[hash_length_bytes];
    EVP_DigestFinal_ex(hash_context, hash_result_bytes, &hash_length_bytes);
    EVP_MD_CTX_free(hash_context);

    // convert the hash digest back to a BIGNUM and return
    BN_bin2bn(hash_result_bytes, hash_length_bytes, hash_result);
    // char *hash_result_hex = BN_bn2hex(hash_result);
    // printf("hash : %s\n", hash_result_hex);
    return hash_result;
};

BIGNUM* BigNumHelpers::sha256BigNum(BIGNUM* bignum_to_hash){
    BIGNUM *hash_result = BN_new();
    unsigned hash_length_bytes = 256/8;

    // convert the bignum into a byte array to be hashed
    size_t size = BN_num_bytes(bignum_to_hash);
    unsigned char *byte_array_to_hash = new unsigned char[size]();
    BN_bn2bin(bignum_to_hash, byte_array_to_hash);

    // Initialize a digest and add the byte arrat to hash to it
    EVP_MD_CTX *hash_context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash_context, EVP_sha256(), NULL);
    EVP_DigestUpdate(hash_context, byte_array_to_hash, size);

    // extracted the hash digest as a byte array
    unsigned char hash_result_bytes[hash_length_bytes];
    EVP_DigestFinal_ex(hash_context, hash_result_bytes, &hash_length_bytes);
    EVP_MD_CTX_free(hash_context);

    // convert the hash digest back to a BIGNUM and return
    BN_bin2bn(hash_result_bytes, hash_length_bytes, hash_result);
    // char *hash_result_hex = BN_bn2hex(hash_result);
    // printf("hash : %s\n", hash_result_hex);
    return hash_result;
};

BIGNUM* BigNumHelpers::sha384BigNum(BIGNUM* bignum_to_hash){
    BIGNUM *hash_result = BN_new();
    unsigned hash_length_bytes = 384/8;

    // convert the bignum into a byte array to be hashed
    size_t size = BN_num_bytes(bignum_to_hash);
    unsigned char *byte_array_to_hash = new unsigned char[size]();
    BN_bn2bin(bignum_to_hash, byte_array_to_hash);

    // Initialize a digest and add the byte arrat to hash to it
    EVP_MD_CTX *hash_context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash_context, EVP_sha384(), NULL);
    EVP_DigestUpdate(hash_context, byte_array_to_hash, size);

    // extracted the hash digest as a byte array
    unsigned char hash_result_bytes[hash_length_bytes];
    EVP_DigestFinal_ex(hash_context, hash_result_bytes, &hash_length_bytes);
    EVP_MD_CTX_free(hash_context);

    // convert the hash digest back to a BIGNUM and return
    BN_bin2bn(hash_result_bytes, hash_length_bytes, hash_result);
    // char *hash_result_hex = BN_bn2hex(hash_result);
    // printf("hash : %s\n", hash_result_hex);
    return hash_result;
};

BIGNUM* BigNumHelpers::sha512BigNum(BIGNUM* bignum_to_hash){
    BIGNUM *hash_result = BN_new();
    unsigned hash_length_bytes = 512/8;

    // convert the bignum into a byte array to be hashed
    size_t byte_size = BN_num_bytes(bignum_to_hash);
    unsigned char *byte_array_to_hash = new unsigned char[byte_size]();
    BN_bn2bin(bignum_to_hash, byte_array_to_hash);

    // Initialize a digest and add the byte arrat to hash to it
    EVP_MD_CTX *hash_context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash_context, EVP_sha512(), NULL);
    EVP_DigestUpdate(hash_context, byte_array_to_hash, byte_size);

    // extracted the hash digest as a byte array
    unsigned char hash_result_bytes[hash_length_bytes];
    EVP_DigestFinal_ex(hash_context, hash_result_bytes, &hash_length_bytes);
    EVP_MD_CTX_free(hash_context);

    // convert the hash digest back to a BIGNUM and return
    BN_bin2bn(hash_result_bytes, hash_length_bytes, hash_result);
    // char *hash_result_hex = BN_bn2hex(hash_result);
    // printf("hash : %s\n", hash_result_hex);
    return hash_result;
};