/// This file handles generation of RSA Keys in C++
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
/// Author        : Jamie Barbour-Moore
/// Created       : 05/12/25
/// Updated       : 05/14/25

#include "RSAKeyGeneration.hpp"

ShaweTaylorRandomPrimeResult::ShaweTaylorRandomPrimeResult(bool success, BIGNUM* prime, BIGNUM* prime_seed, int prime_gen_counter){
    success_ = success;
    prime_ = BN_new();
    OPENSSL_assert(BN_copy(prime_, prime) != NULL);
    prime_seed_ = BN_new();
    OPENSSL_assert(BN_copy(prime_seed_, prime_seed) != NULL);
    prime_gen_counter_ = prime_gen_counter;
}

ShaweTaylorRandomPrimeResult::ShaweTaylorRandomPrimeResult(){
    success_ = false;
    prime_ = BN_new();
    prime_seed_ = BN_new();
    prime_gen_counter_ = 0;
}

void ShaweTaylorRandomPrimeResult::freeResult(){
    if(prime_){
        BN_free(prime_);
    }
    if(prime_seed_){
        BN_free(prime_seed_);
    }
}

ProvablePrimeGenerationResult::ProvablePrimeGenerationResult(bool success, BIGNUM* prime, BIGNUM* prime_1, BIGNUM* prime_2, BIGNUM* prime_seed){
    success_ = success;
    
    prime_ = BN_new();
    OPENSSL_assert(BN_copy(prime_, prime) != NULL);
    prime_1_ = BN_new();
    OPENSSL_assert(BN_copy(prime_1_, prime_1) != NULL);
    prime_2_ = BN_new();
    OPENSSL_assert(BN_copy(prime_2_, prime_2) != NULL);
    prime_seed_ = BN_new();
    OPENSSL_assert(BN_copy(prime_seed_, prime_seed) != NULL);
}
ProvablePrimeGenerationResult::ProvablePrimeGenerationResult(){
    success_ = false;
    prime_ = BN_new();
    prime_1_ = BN_new();
    prime_2_ = BN_new();
    prime_seed_ = BN_new();
}

void ProvablePrimeGenerationResult::freeResult(){
    if(prime_){
        BN_free(prime_);
    }
    if(prime_1_){
        BN_free(prime_1_);
    }
    if(prime_2_){
        BN_free(prime_2_);
    }
    if(prime_seed_){
        BN_free(prime_seed_);
    }
}

RSAKeyGenerationResult::RSAKeyGenerationResult(bool success, RSAPrivateKey private_key, RSAPublicKey public_key, int key_length){
    success_ = success;
    private_key_ = private_key;
    public_key_ = public_key;
    key_length_ = key_length;
}

ConstructPandQResult::ConstructPandQResult(bool success, BIGNUM *p, BIGNUM *q){
    success_ = success;
    p_ = BN_new();
    BN_copy(p_, p);
    q_ = BN_new();
    BN_copy(q_, q);
}

ConstructPandQResult::ConstructPandQResult(){
    success_ = false;
    p_ = BN_new();
    q_ = BN_new();
}

void ConstructPandQResult::freeResult(){
    if(p_){
        BN_free(p_);
    }
    if(q_){
        BN_free(q_);
    }
}