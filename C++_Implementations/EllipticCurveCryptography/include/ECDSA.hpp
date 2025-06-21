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
        PerMessageSecret();
        PerMessageSecret(BIGNUM *n);
        PerMessageSecret(std::string k_hex, BIGNUM* n);
        void generateSecret(BIGNUM *n);
        void loadSecret(std::string k_hex, BIGNUM *n);
        void deleteSecret();
};

struct ECDSA_Signature {
    public :
        BIGNUM* r_;
        BIGNUM* s_;

        ECDSA_Signature(BIGNUM *r, BIGNUM *s);
        ECDSA_Signature(std::string r_hex, std::string s_hex);
        void print();
        bool operator==(const ECDSA_Signature &input) const;
};

class ECDSA {
    private :
        WeirrstrassCurve curve_;

        EllipticCurves curve_type_;

        void hash(BIGNUM *value, BIGNUM *result);

    public : 
        ECDSA(EllipticCurves curve_type);

        ECDSA_Signature SignatureGeneration(std::string M_hex, BIGNUM *d, std::string k_hex = "");

        ECDSA_Signature SignatureGeneration(std::string message, std::string d_hex);

        ECDSA_Signature SignatureGeneration(std::string message, std::string d_hex, std::string k_hex);

};

#endif
