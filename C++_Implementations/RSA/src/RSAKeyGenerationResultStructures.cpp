/// This file handles generation of RSA Keys in C++
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
/// Author        : Jamie Barbour-Moore
/// Created       : 05/12/25
/// Updated       : 05/14/25

#include "RSAKeyGeneration.hpp"

ShaweTaylorRandomPrimeResult::ShaweTaylorRandomPrimeResult(bool success, BIGNUM* prime, BIGNUM* prime_seed, int prime_gen_counter){
    result_ctx_ = BN_CTX_secure_new();
    BN_CTX_start(result_ctx_);
    success_ = success;
    prime_ = BN_CTX_get(result_ctx_);
    OPENSSL_assert(BN_copy(prime_, prime) != NULL);
    prime_seed_ = BN_CTX_get(result_ctx_);
    OPENSSL_assert(BN_copy(prime_seed_, prime_seed) != NULL);
    prime_gen_counter_ = prime_gen_counter;
}

void ShaweTaylorRandomPrimeResult::freeResult(){
    BN_CTX_end(result_ctx_);
    BN_CTX_free(result_ctx_);
}

ProvablePrimeGenerationResult::ProvablePrimeGenerationResult(bool success, BIGNUM* prime, BIGNUM* prime_1, BIGNUM* prime_2, BIGNUM* prime_seed){
    success_ = success;
    result_ctx_ = BN_CTX_secure_new();
    BN_CTX_start(result_ctx_);
    prime_ = BN_CTX_get(result_ctx_);
    OPENSSL_assert(BN_copy(prime_, prime) != NULL);
    prime_1_ = BN_CTX_get(result_ctx_);
    OPENSSL_assert(BN_copy(prime_1_, prime_1) != NULL);
    prime_2_ = BN_CTX_get(result_ctx_);
    OPENSSL_assert(BN_copy(prime_2_, prime_2) != NULL);
    prime_seed_ = BN_CTX_get(result_ctx_);
    OPENSSL_assert(BN_copy(prime_seed_, prime_seed) != NULL);
}
ProvablePrimeGenerationResult::ProvablePrimeGenerationResult(){
    success_ = false;
    result_ctx_ = BN_CTX_secure_new();
    BN_CTX_start(result_ctx_);
    prime_ = BN_CTX_get(result_ctx_);
    prime_1_ = BN_CTX_get(result_ctx_);
    prime_2_ = BN_CTX_get(result_ctx_);
    prime_seed_ = BN_CTX_get(result_ctx_);
}

void ProvablePrimeGenerationResult::freeResult(){
    BN_CTX_end(result_ctx_);
    BN_CTX_free(result_ctx_);
}


RSAKeyGenerationResult::RSAKeyGenerationResult(bool success, RSAPrivateKey private_key, RSAPublicKey public_key, int key_length){
    success_ = success;
    private_key_ = private_key;
    public_key_ = public_key;
    key_length_ = key_length;
}

ConstructPandQResult::ConstructPandQResult(bool success, BIGNUM *p, BIGNUM *q){
    success_ = success;
    p_ = p;
    q_ = q;
}