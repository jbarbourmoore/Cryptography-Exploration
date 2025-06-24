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
    BN_mod_inverse(inverse_, value_, n, gen_ctx);
}

PerMessageSecret::PerMessageSecret(){
    gen_ctx = BN_CTX_secure_new();
    BN_CTX_start(gen_ctx);
    value_ = BN_CTX_get(gen_ctx);
    inverse_ = BN_CTX_get(gen_ctx);
}

PerMessageSecret::PerMessageSecret(std::string k_hex, BIGNUM* n){
    gen_ctx = BN_CTX_secure_new();
    BN_CTX_start(gen_ctx);
    value_ = BN_CTX_get(gen_ctx);
    inverse_ = BN_CTX_get(gen_ctx);
    BN_hex2bn(&value_, k_hex.c_str());
    BN_mod_inverse(inverse_, value_, n, gen_ctx);
}

void PerMessageSecret::generateSecret(BIGNUM *n){
    BN_priv_rand_range(value_, n);
    BN_mod_inverse(inverse_, value_, n, gen_ctx);
}

void PerMessageSecret::loadSecret(std::string k_hex, BIGNUM *n){
    BN_hex2bn(&value_, k_hex.c_str());
    BN_mod_inverse(inverse_, value_, n, gen_ctx);
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

ECDSA_Signature::ECDSA_Signature(std::string r_hex, std::string s_hex){
    s_ = BN_new();
    r_ = BN_new();
    BN_hex2bn(&r_, r_hex.c_str());
    BN_hex2bn(&s_, s_hex.c_str());
}

void ECDSA_Signature::print(){
    printf("r: %s\n", BN_bn2hex(r_));
    printf("s: %s\n", BN_bn2hex(s_));
}

bool ECDSA_Signature::operator==(const ECDSA_Signature &input) const{
    int s_comp = BN_cmp(s_, input.s_);
    int r_comp = BN_cmp(r_, input.r_);
    
    bool result = s_comp == 0 && r_comp == 0;
    return result;
}

void ECDSA::calculateE(BIGNUM *result, BIGNUM *M){
    BIGNUM *H = BN_new();
    hash(M, H);
    int hash_length = BN_num_bits(M);
    int n_length = BN_num_bits(curve_.getN());
    if( n_length > hash_length){
        BN_copy(result, H);
    } else {
        BN_rshift(result, H, hash_length - n_length);
    }
    BN_clear_free(H);
}

ECDSA_Signature ECDSA::SignatureGeneration(std::string M_hex, BIGNUM *d, std::string k_hex){
    BN_CTX *gen_ctx = BN_CTX_secure_new();

    BIGNUM *M = BN_CTX_get(gen_ctx);
    BIGNUM *E = BN_CTX_get(gen_ctx);
    BIGNUM *r = BN_CTX_get(gen_ctx);
    BIGNUM *s = BN_CTX_get(gen_ctx);

    BN_hex2bn(&M, M_hex.c_str());

    calculateE(E, M);
    printf("starting\n");
    printf("E : %s\n", BN_bn2hex(E));

    while(BN_is_zero(s) == 1 || BN_is_zero(r) == 1){
        PerMessageSecret k;
        if(k_hex == ""){
            k.generateSecret(curve_.getN());
        } else {
            k.loadSecret(k_hex,  curve_.getN());
        }
        printf("k : %s\n", BN_bn2hex(k.value_));
        printf("k inv : %s\n", BN_bn2hex(k.inverse_));
        printf("n : %s\n", BN_bn2hex(curve_.getN()));

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

ECDSA_Signature ECDSA::SignatureGeneration(std::string message, std::string d_hex){
    BIGNUM *d = BN_new();
    BN_hex2bn(&d, d_hex.c_str());

    // printf("message : %s\n", message.c_str());
    int length = message.size();
    std::string m_hex = "";

    for (int i = 0; i < length; i++){
        char new_char[3];
        sprintf(new_char, "%02X", message[i]);
        m_hex = m_hex + new_char[0] + new_char[1];
    }

    ECDSA_Signature signature = SignatureGeneration(m_hex, d);

    BN_clear_free(d);

    return signature;
}

ECDSA_Signature ECDSA::SignatureGeneration(std::string message, std::string d_hex, std::string k_hex){
    BIGNUM *d = BN_new();
    BN_hex2bn(&d, d_hex.c_str());

    std::string m_hex = stringToHexString(message);

    ECDSA_Signature signature = SignatureGeneration(m_hex, d, k_hex);

    BN_clear_free(d);

    return signature;
}

bool ECDSA::SignatureVerificationFromHex(std::string M_hex, Point Q, ECDSA_Signature signature){
    bool result = false;

    bool r_in_range = BN_cmp(signature.r_, curve_.getN()) == -1 && BN_is_negative(signature.r_) == 0;
    int s_in_range = BN_cmp(signature.s_, curve_.getN()) == -1 && BN_is_negative(signature.s_) == 0;

    if(r_in_range && s_in_range){

        BN_CTX *ver_ctx = BN_CTX_secure_new();

        BIGNUM *M = BN_CTX_get(ver_ctx);
        BIGNUM *E = BN_CTX_get(ver_ctx);
        BIGNUM *s_inv = BN_CTX_get(ver_ctx);
        BIGNUM *u = BN_CTX_get(ver_ctx);
        BIGNUM *v = BN_CTX_get(ver_ctx);
        BIGNUM *r1 = BN_CTX_get(ver_ctx);

        BN_hex2bn(&M, M_hex.c_str());

        calculateE(E, M);

        BN_mod_inverse(s_inv, signature.s_, curve_.getN(), ver_ctx);

        BN_mul(u, E, s_inv, ver_ctx);
        BN_mul(v, signature.r_, s_inv, ver_ctx);

        Point uG = curve_.calculatePointMultiplicationByConstant(curve_.getG(), u);
        Point vQ = curve_.calculatePointMultiplicationByConstant(Q, v);

        Point R1 = curve_.calculatePointAddition(uG, vQ);
        Point identity_point = Point();
        if(!(R1 == identity_point)){
            BN_copy(r1, R1.getXAsBN());
            curve_.calculatePositiveMod(r1, curve_.getN(), ver_ctx);
            if(BN_cmp(signature.r_, r1) == 0){
                result = true;
            }
        }
    }

    return result;
}

bool ECDSA::SignatureVerification(std::string message, Point Q, ECDSA_Signature signature){
    std::string m_hex = stringToHexString(message);

    return SignatureVerificationFromHex(m_hex, Q, signature);
}

std::string ECDSA::stringToHexString(std::string input){
    int length = input.size();
    std::string hex_string = "";

    for (int i = 0; i < length; i++){
        char new_char[3];
        sprintf(new_char, "%02X", input[i]);
        hex_string = hex_string + new_char[0] + new_char[1];
    }

    return hex_string;
}