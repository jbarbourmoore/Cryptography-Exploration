#include "EllipticCurve.hpp"

void EllipticCurve::calculatePositiveMod(BIGNUM *value, BIGNUM *modulus, BN_CTX *calc_ctx){
    BN_mod(value, value, modulus, calc_ctx);
    if(BN_is_negative(value) == 1){
        BN_add(value, modulus, value);
    }
}