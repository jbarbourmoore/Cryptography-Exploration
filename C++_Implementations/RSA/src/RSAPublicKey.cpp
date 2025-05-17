/// This is my implementation for RSA Public Key in C++
///
/// Libaries Used : OpenSSL BIGNUM for dealing with extremely large integers
/// Author        : Jamie Barbour-Moore
/// Created       : 05/11/25
/// Updated       : 05/12/25

#include "RSAPublicKey.hpp"

RSAPublicKey::RSAPublicKey(BIGNUM *n, BIGNUM *e, int keylength){
    n_ = BN_new();
    BN_copy(n_, n);
    e_  = BN_new();
    BN_copy(e_, e);
    keylength_ = keylength;
}

RSAPublicKey::RSAPublicKey(int keylength){
    keylength_ = keylength;
}

void RSAPublicKey::fromDecCharArray(const char *charArrayN, const char *charArrayE, int keylength){
    BN_dec2bn(&n_, charArrayN);
    BN_dec2bn(&e_, charArrayE);
    keylength_ = keylength;
};

void RSAPublicKey::fromHexCharArray(const char *charArrayN, const char *charArrayE, int keylength){
    BN_hex2bn(&n_, charArrayN);
    BN_hex2bn(&e_, charArrayE);
    keylength_ = keylength;
};

void RSAPublicKey::printKey(){
    char *hexN = BN_bn2hex(n_);
    char *hexE = BN_bn2hex(e_);

    printf("Public Key With Bit Length %i\n", keylength_);
    printf("n : %s\n", hexN);
    printf("e : %s\n", hexE);

    OPENSSL_free(hexN);
    OPENSSL_free(hexE);
};

void RSAPublicKey::freeKey(){
    BN_free(e_);
    BN_free(n_);
    BN_CTX_free(context_);
};

char* RSAPublicKey::getHexN(){
    char *ouputChars = BN_bn2hex(n_);
    return ouputChars;
};

char* RSAPublicKey::getHexE(){
    char *ouputChars = BN_bn2hex(e_);
    return ouputChars;
};

int RSAPublicKey::getKeyLength(){
    return keylength_;
};

char* RSAPublicKey::encryptionPrimitive(char const *charArrayMessage){
    BIGNUM *message = BN_new();
    BN_hex2bn(&message, charArrayMessage);

    BIGNUM *encrypted = BN_new();
    
    BN_mod_exp(encrypted, message, e_, n_, context_);

    char *encrypted_hex = BN_bn2hex(encrypted);

    BN_free(message);
    BN_free(encrypted);

    return encrypted_hex;
};
