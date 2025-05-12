#ifndef RSAKeyGeneration_HPP
#define RSAKeyGeneration_HPP

#include <openssl/bn.h>
#include <string.h>

/// @brief This class contains the variables and methods for an RSA Private Key
class RSAKeyGeneration{

    private:
        /// @brief The RSA Private Key modulus
        BIGNUM *n_ {NULL};

        /// @brief The RSA Private Key exponent
        BIGNUM *d_ {NULL};

        /// @brief the key length in bits
        int keylength_ {2048};

    public:
        /// @brief This method returns the security strength for the RSA Key Generation basec on the key length
        /// @return The security strength
        int getSecurityStrength();

        /// @brief This method returns the security strength for the RSA Key Generation
        /// @return The key length in bits
        int getKeyLength();

};

#endif