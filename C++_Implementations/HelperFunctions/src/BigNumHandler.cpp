#include "BigNumHelpers.hpp"

PassBigNum::PassBigNum(BIGNUM *bn){
    bn_ = BN_secure_new();
    BIGNUM *verification = BN_copy(bn_, bn);
    OPENSSL_assert(verification == bn_);
}

void PassBigNum::copyAndClear(BIGNUM *destination_pointer){
    // char *bnhex = BN_bn2hex(bn_);
    // printf("bn hex %s\n", bnhex);
    BIGNUM *verification = BN_copy(destination_pointer, bn_);
    OPENSSL_assert(verification == destination_pointer);
    OPENSSL_assert(destination_pointer != NULL);
    // char *hex = BN_bn2hex(destination_pointer);
    // printf("dest %s\n", hex);
    freePassedBN();
    OPENSSL_assert(destination_pointer != NULL);
    // hex = BN_bn2hex(destination_pointer);
    // printf("dest %s\n", hex);
}

void PassBigNum::freePassedBN(){
    BN_clear_free(bn_);
}

void BigNumHelpers::getBNCopyInContext(BIGNUM* destination_pointer, BIGNUM *starting_pointer, BN_CTX *destination_ctx){
    
    destination_pointer = BN_CTX_get(destination_ctx);
    // char *hex = BN_bn2hex(destination_pointer);
    // printf("dest %s\n", hex);
    OPENSSL_assert(destination_pointer != nullptr);
    BIGNUM *verification = BN_copy(destination_pointer, starting_pointer);
    // hex = BN_bn2hex(destination_pointer);
    // printf("dest %s\n", hex);
    OPENSSL_assert(verification == destination_pointer);
    OPENSSL_assert(destination_pointer != NULL);

}
