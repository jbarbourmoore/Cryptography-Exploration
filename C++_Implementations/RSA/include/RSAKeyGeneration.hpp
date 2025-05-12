#ifndef RSAKeyGeneration_HPP
#define RSAKeyGeneration_HPP

#include <openssl/bn.h>
#include <string.h>

/// @brief This class contains the variables and methods for an RSA Private Key
class RSAKeyGeneration{

    private:
        /// @brief The minimum value for e (the public exponent)
        BIGNUM *e_min_ { BN_new() };

        /// @brief The maximum value for e (the public exponent)
        BIGNUM *e_max_ { BN_new() };

        /// @brief The minimum difference between 'p' and 'q'
        BIGNUM *min_pq_diff_ { BN_new() };

        /// @brief The minimum value for both 'p' and 'q'
        BIGNUM *min_prime_value_ { BN_new() };

        /// @brief the key length in bits
        int keylength_ {2048};

        /// @brief This method sets the parameters for e
        void setEParameters();

        /// @brief This method sets the minimum difference between 'p' and 'q'
        void setMinPQDiff();

        /// @brief This method sets the minimum value for both 'p' and 'q'
        void setMinPrimeValue();

    public:

        /// @brief Instantiates RSAKeyGeneration with a given keylength in bits
        /// @param keylength The key length in bits to be used for the RSA Key Generation, default is 2048
        RSAKeyGeneration(int keylength = 2048);

        /// @brief This method returns the security strength for the RSA Key Generation basec on the key length
        /// @return The security strength
        int getSecurityStrength();

        /// @brief This method returns the key length for the RSA Key Generation
        /// @return The key length in bits
        int getKeyLength();

        /// @brief This method returns the bit length for each large prime for the RSA Key Generation
        /// @return The prime length in bits
        int getPrimeLength();

};

#endif