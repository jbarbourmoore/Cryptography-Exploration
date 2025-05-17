/// This is my implementation for RSA Private Key in C++
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
/// Author        : Jamie Barbour-Moore
/// Created       : 05/11/25
/// Updated       : 05/14/25

#include <openssl/bn.h>
#include <string.h>
#include "RSAPrivateKey.hpp"

RSAPrivateKey::RSAPrivateKey(BIGNUM *n, BIGNUM *d, int key_length){
    keylength_ = key_length;
    n_ = BN_new();
    BN_copy(n_, n);
    d_  = BN_new();
    BN_copy(d_, d);
    quint_form_ = false;
}

RSAPrivateKey::RSAPrivateKey(BIGNUM *n, BIGNUM *d, BIGNUM *p, BIGNUM *q, int key_length){
    keylength_ = key_length;
    n_ = BN_new();
    BN_copy(n_, n);
    d_  = BN_new();
    BN_copy(d_, d);
    p_ = BN_new();
    BN_copy(p_, p);
    q_  = BN_new();
    BN_copy(q_, q);
    quint_form_ = true;
    populateQuintForm();
}

RSAPrivateKey::RSAPrivateKey(int key_length){
    keylength_ = key_length;
}

void RSAPrivateKey::fromDecCharArray(const char *charArrayN, const char *charArrayD, int keylength){
    BN_dec2bn(&n_, charArrayN);
    BN_dec2bn(&d_, charArrayD);
    keylength_ = keylength;
    quint_form_ = false;
};

void RSAPrivateKey::fromHexCharArray(const char *charArrayN, const char *charArrayD, int keylength){
    BN_hex2bn(&n_, charArrayN);
    BN_hex2bn(&d_, charArrayD);
    keylength_ = keylength;
    quint_form_ = false;
};

void RSAPrivateKey::fromDecCharArray_QuintForm(const char *charArrayN, const char *charArrayD, const char *charArrayP, const char *charArrayQ, int keylength){
    BN_dec2bn(&n_, charArrayN);
    BN_dec2bn(&d_, charArrayD);
    BN_dec2bn(&p_, charArrayP);
    BN_dec2bn(&q_, charArrayQ);
    keylength_ = keylength;
    quint_form_ = true;
    populateQuintForm();
}

void RSAPrivateKey::fromHexCharArray_QuintForm(const char *charArrayN, const char *charArrayD, const char *charArrayP, const char *charArrayQ, int keylength){
    BN_hex2bn(&n_, charArrayN);
    BN_hex2bn(&d_, charArrayD);
    BN_hex2bn(&p_, charArrayP);
    BN_hex2bn(&q_, charArrayQ);
    keylength_ = keylength;
    quint_form_ = true;
    printf("successful inputs\n");
    populateQuintForm();
}

void RSAPrivateKey::populateQuintForm(){
    dP_ = BN_new();
    dQ_ = BN_new();
    qInv_ = BN_new();
    BIGNUM *q_dec = BN_new();
    BIGNUM *p_dec = BN_new();
    BIGNUM *big_one = BN_new();
    BN_one(big_one);
    BN_usub(q_dec, q_, big_one);
    BN_usub(p_dec, p_, big_one);
    BN_mod(dP_, d_, p_dec, context_);
    BN_mod(dQ_, d_, q_dec, context_);
    BN_mod_inverse(qInv_, q_, p_, context_);
}

char* RSAPrivateKey::decryptionPrimitive(char const *charArrayCypherText){
    BIGNUM *cipher_text = BN_new();
    BN_hex2bn(&cipher_text, charArrayCypherText);
    BIGNUM *message = BN_new();

    if (!quint_form_){ 
        BN_mod_exp(message, cipher_text, d_, n_, context_);
    }else{
        BIGNUM *m1 = BN_new();
        BIGNUM *m2 = BN_new();
        BN_mod_exp(m1, cipher_text, dP_, p_, context_);
        BN_mod_exp(m2, cipher_text, dQ_, q_, context_);

        BIGNUM *sub_m1_m2 = BN_new();
        BN_sub(sub_m1_m2,m1,m2);
        BIGNUM *h = BN_new();
        BN_mod_mul(h, sub_m1_m2, qInv_, p_, context_);
        BIGNUM *q_h = BN_new();
        BN_mul(q_h, q_, h, context_);
        BN_add(message, m2, q_h);

        BN_free(q_h);
        BN_free(h);
        BN_free(sub_m1_m2);
        BN_free(m1);
        BN_free(m2);
    }
    char *message_hex = BN_bn2hex(message);
    BN_free(message);
    return message_hex;
};

bool RSAPrivateKey::isQuintForm(){
    return quint_form_;
}

char* RSAPrivateKey::getHexN(){
    char *ouputChars = BN_bn2hex(n_);
    return ouputChars;
};

char* RSAPrivateKey::getHexD(){
    char *ouputChars = BN_bn2hex(d_);
    return ouputChars;
};

int RSAPrivateKey::getKeyLength(){
    return keylength_;
};

void RSAPrivateKey::printKey(){
    char *hexN = BN_bn2hex(n_);
    char *hexD = BN_bn2hex(d_);

    printf("Public Key With Bit Length %i\n", keylength_);
    printf("n    : %s\n", hexN);
    printf("d    : %s\n", hexD);

    OPENSSL_free(hexN);
    OPENSSL_free(hexD);
    if (quint_form_) {
        char *hexP = BN_bn2hex(p_);
        char *hexQ = BN_bn2hex(q_);
        char *hexDP = BN_bn2hex(dP_);
        char *hexDQ = BN_bn2hex(dQ_);
        char *hexQInv = BN_bn2hex(qInv_);
        printf("p    : %s\n", hexP);
        printf("q    : %s\n", hexQ);
        printf("dP   : %s\n", hexDP);
        printf("dQ   : %s\n", hexDQ);
        printf("qInv : %s\n", hexQInv);
        OPENSSL_free(hexP);
        OPENSSL_free(hexQ);
        OPENSSL_free(hexDP);
        OPENSSL_free(hexDQ);
        OPENSSL_free(hexQInv);
    }
};

void RSAPrivateKey::freeKey(){
    BN_free(d_);
    BN_free(n_);
    if (quint_form_){
        BN_free(p_);
        BN_free(q_);
        BN_free(dP_);
        BN_free(dQ_);
        BN_free(qInv_);
        BN_CTX_free(context_);
    }
};
