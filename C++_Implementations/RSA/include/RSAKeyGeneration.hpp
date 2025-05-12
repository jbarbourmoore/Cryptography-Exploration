#ifndef RSAKeyGeneration_HPP
#define RSAKeyGeneration_HPP

#include <openssl/bn.h>
#include <string.h>
#include <cassert>

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

        /// @brief The current value for 'e'
        BIGNUM *e_ { BN_new() };

        /// @brief The current value for 'p'
        BIGNUM *p_ { BN_new() };

        /// @brief The current value for 'q'
        BIGNUM *q_ { BN_new() };

        /// @brief The current value for 'seed'
        BIGNUM *seed_ { BN_new() };

        /// @brief the key length in bits
        int keylength_ {2048};

        /// @brief The BN CTX to be used in the calculations for this rsa key generation
        BN_CTX *context_ = BN_CTX_new();

        /// @brief This method sets the parameters for e
        void setEParameters();

        /// @brief This method sets the minimum difference between 'p' and 'q'
        void setMinPQDiff();

        /// @brief This method sets the minimum value for both 'p' and 'q'
        void setMinPrimeValue();

        /// @brief This method generates a seed value to be used in generating provable primes
        /// Based on Nist Fips 186-5 Appendix A.1.2.1 "Get the seed"
        void generateRandomSeed();

        /// @brief This method generates a random public exponenent to be used in the RSA keys
        void generateRandomE();

        /// @brief This method generates the provable primes 'p' and 'q' to be used in the RSA keys
        /// Based on Nist Fips 186-5 Appendix A.1.2.2 "Construction of the Provable Primes p and q"
        void constructTheProvablePrimes();

    public:

        /// @brief Instantiates RSAKeyGeneration with a given keylength in bits
        /// @param keylength The key length in bits to be used for the RSA Key Generation, default is 2048
        RSAKeyGeneration(int keylength = 2048);

        /// @brief This method generates RSA keys based on provable primes.
        /// Based on Nist Fips 186-5 Appendix A.1.2 "Generation of Random Primes that are Provably Prime"
        void generateRSAKeysUsingProvablePrimes();

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