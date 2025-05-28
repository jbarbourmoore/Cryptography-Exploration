#include "BigNumHelpers.hpp"

std::string BigNumHelpers::getSecureRandBits(int bit_length){
    BIGNUM *new_rand = BN_new();
    BN_rand(new_rand, bit_length, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    char *output = BN_bn2hex(new_rand);
    std::string random = std::string(output);
    BN_clear_free(new_rand);
    return random;
}