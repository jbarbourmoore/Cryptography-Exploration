#ifndef EdDSA_HPP
#define EdDSA_HPP

#include <openssl/bn.h>
#include "Point.hpp"
#include "EdwardsCurve.hpp"
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

struct EdDSA_Signature {
    public :
        BIGNUM* r_;
        BIGNUM* s_;

        EdDSA_Signature(BIGNUM *r, BIGNUM *s);
        EdDSA_Signature(std::string r_hex, std::string s_hex);
        void print();
        bool operator==(const EdDSA_Signature &input) const;
};

class EdDSA {
    private :
        EdwardsCurve curve_;

        EllipticCurves curve_type_;

        void hash(BIGNUM *value, BIGNUM *result);

        std::string stringToHexString(std::string input);

        void calculateE(BIGNUM *result, BIGNUM *M);

    public : 
        EdDSA(EllipticCurves curve_type);

        EdDSA_Signature SignatureGeneration(std::string M_hex, BIGNUM *d, std::string k_hex = "");

        EdDSA_Signature SignatureGeneration(std::string message, std::string d_hex);

        EdDSA_Signature SignatureGeneration(std::string message, std::string d_hex, std::string k_hex);

        bool SignatureVerificationFromHex(std::string M_hex, Point Q, EdDSA_Signature signature);

        bool SignatureVerification(std::string message, Point Q, EdDSA_Signature signature);

};

#endif
