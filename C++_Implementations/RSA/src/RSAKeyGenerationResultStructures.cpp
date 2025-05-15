/// This file handles generation of RSA Keys in C++
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
/// Author        : Jamie Barbour-Moore
/// Created       : 05/12/25
/// Updated       : 05/14/25

#include "RSAKeyGeneration.hpp"

ShaweTaylorRandomPrimeResult::ShaweTaylorRandomPrimeResult(bool success, BIGNUM* prime, BIGNUM* prime_seed, int prime_gen_counter){
    success_ = success;
    prime_ = prime;
    prime_seed_ = prime_seed;
    prime_gen_counter_ = prime_gen_counter;
}

ProvablePrimeGenerationResult::ProvablePrimeGenerationResult(bool success, BIGNUM* prime, BIGNUM* prime_1, BIGNUM* prime_2, BIGNUM* prime_seed){
    success_ = success;
    prime_ = prime;
    prime_1_ = prime_1;
    prime_2_ = prime_2;
    prime_seed_ = prime_seed;
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