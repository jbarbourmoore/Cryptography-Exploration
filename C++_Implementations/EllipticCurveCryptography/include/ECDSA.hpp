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

        std::string stringToHexString(std::string input);

        void calculateE(BIGNUM *result, BIGNUM *M);

    public : 
        ECDSA(EllipticCurves curve_type);

        ECDSA_Signature SignatureGeneration(std::string M_hex, BIGNUM *d, std::string k_hex = "");

        ECDSA_Signature SignatureGeneration(std::string message, std::string d_hex);

        ECDSA_Signature SignatureGeneration(std::string message, std::string d_hex, std::string k_hex);

        bool SignatureVerificationFromHex(std::string M_hex, Point Q, ECDSA_Signature signature);

        bool SignatureVerification(std::string message, Point Q, ECDSA_Signature signature);

        std::string generateHexStringPrivateKey();

        Point calculatePublicKey(std::string private_key);

        std::string calculateHexStringPublicKeyX(std::string private_key);

        std::string calculateHexStringPublicKeyY(std::string private_key);

};

#endif
