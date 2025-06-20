#ifndef ECDSA_HPP
#define ECDSA_HPP

#include <openssl/bn.h>
#include "Point.hpp"
#include "EllipticCurve.hpp"
#include "BigNumHelpers.hpp"


struct PerMessageSecret {
    public: 
        BIGNUM* value_;
        BIGNUM* inverse_;
        BN_CTX *gen_ctx;
        PerMessageSecret(BIGNUM *n);
        void deleteSecret();
};

struct ECDSA_Signature {
    public :
        BIGNUM* r_;
        BIGNUM* s_;

        ECDSA_Signature(BIGNUM *r, BIGNUM *s);
};

class ECDSA {
    private :
        WeirrstrassCurve curve_;

        EllipticCurves curve_type_;

        void hash(BIGNUM *value, BIGNUM *result);

    public : 
        ECDSA(EllipticCurves curve_type);

        ECDSA_Signature SignatureGeneration(std::string M_hex, BIGNUM *d);

};

#endif
