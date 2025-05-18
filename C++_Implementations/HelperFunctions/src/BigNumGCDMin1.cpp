#include "BigNumHelpers.hpp"

void BigNumHelpers::gcdValueMinusOneSecondValue(BIGNUM* result, BIGNUM* first_value, BIGNUM* second_value){
    BN_CTX *context = BN_CTX_secure_new();
    BN_CTX_start(context);

    BIGNUM *value_minus_one = BN_CTX_get(context);

    BN_copy(value_minus_one, first_value);
    BN_sub_word(value_minus_one, 1);

    BN_gcd(result, value_minus_one, second_value, context);

    BN_CTX_end(context);
    BN_CTX_free(context);
}