#include "ECDSA.hpp"

ECDSA::ECDSA(EllipticCurves curve_type){
    curve_type_ = curve_type;

    switch(curve_type){
        case (EllipticCurves::SECP192R1_):{
            curve_ = secp192r1();
            break;
        }
        case (EllipticCurves::SECP224R1_):{
            curve_ = secp224r1();
            break;
        }
        case (EllipticCurves::SECP256R1_):{
            curve_ = secp256r1();
            break;
        }
        case (EllipticCurves::SECP384R1_):{
            curve_ = secp384r1();
            break;
        }
        case (EllipticCurves::SECP521R1_):{
            curve_ = secp521r1();
            break;
        }
        default:{
            curve_ = secp521r1();
        }
    }
}

void ECDSA::hash(BIGNUM *input_bn, BIGNUM *result){
    switch(curve_type_){
        case (EllipticCurves::SECP192R1_):{
            BigNumHelpers::sha224BigNum(result, input_bn);
            break;
        }
        case (EllipticCurves::SECP224R1_):{
            BigNumHelpers::sha224BigNum(result, input_bn);
            break;
        }
        case (EllipticCurves::SECP256R1_):{
            BigNumHelpers::sha256BigNum(result, input_bn);
            break;
        }
        case (EllipticCurves::SECP384R1_):{
            BigNumHelpers::sha384BigNum(result, input_bn);
            break;
        }
        case (EllipticCurves::SECP521R1_):{
            BigNumHelpers::sha512BigNum(result, input_bn);
            break;
        }
        default:{
            BigNumHelpers::sha512BigNum(result, input_bn);
        }
    }
}

PerMessageSecret::PerMessageSecret(BIGNUM* n){
    gen_ctx = BN_CTX_secure_new();
    BN_CTX_start(gen_ctx);
    value_ = BN_CTX_get(gen_ctx);
    inverse_ = BN_CTX_get(gen_ctx);
    BN_priv_rand_range(value_, n);
    BN_mod_inverse(inverse_, n, value_, gen_ctx);
}

void PerMessageSecret::deleteSecret(){
    BN_CTX_end(gen_ctx);
    BN_CTX_free(gen_ctx);
}

ECDSA_Signature::ECDSA_Signature(BIGNUM *r, BIGNUM *s){
    s_ = BN_new();
    r_ = BN_new();
    BN_copy(r_, r);
    BN_copy(s_, s);
}

ECDSA_Signature ECDSA::SignatureGeneration(std::string M_hex, BIGNUM *d){
    BN_CTX *gen_ctx = BN_CTX_secure_new();

    BIGNUM *M = BN_CTX_get(gen_ctx);
    BIGNUM *H = BN_CTX_get(gen_ctx);
    BIGNUM *E = BN_CTX_get(gen_ctx);
    BIGNUM *r = BN_CTX_get(gen_ctx);
    BIGNUM *s = BN_CTX_get(gen_ctx);

    BN_hex2bn(&M, M_hex.c_str());

    hash(M, H);
    BN_copy(E, H);

    while(BN_is_zero(s) == 1 || BN_is_zero(r) == 1){
        PerMessageSecret k = PerMessageSecret(curve_.getN());

        Point R = curve_.calculatePointMultiplicationByConstant(curve_.getG(), k.value_);

        BN_copy(r, R.getXAsBN());

        curve_.calculatePositiveMod(r, curve_.getN(), gen_ctx);

        BN_mul(s, r, d, gen_ctx);
        BN_add(s, s, E);
        BN_mul(s, k.inverse_, s, gen_ctx);
        BN_mod(s, s, curve_.getN(), gen_ctx);

        k.deleteSecret();
    }

    return ECDSA_Signature(r, s);
}