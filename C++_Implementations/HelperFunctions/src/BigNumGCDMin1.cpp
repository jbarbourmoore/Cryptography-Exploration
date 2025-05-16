#include "BigNumHelpers.hpp"

BIGNUM* BigNumHelpers::gcdValueMinusOneSecondValue(BIGNUM* first_value, BIGNUM* second_value){
    BIGNUM *value_minus_one = BN_new();
    BN_copy(value_minus_one, first_value);
    BN_sub_word(value_minus_one, 1);

    BN_CTX *context = BN_CTX_new();
    BIGNUM *gcd = BN_new();
    BN_gcd(gcd, value_minus_one, second_value, context);

    BN_free(value_minus_one);
    BN_CTX_free(context);

    return gcd;
}