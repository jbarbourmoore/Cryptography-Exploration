#ifndef RSAKeyGeneration_HPP
#define RSAKeyGeneration_HPP

#include <openssl/bn.h>
#include <string.h>
#include <cassert>
#include "BigNumHelpers.hpp"


/// @brief This structure holds the data from construction of a provable prime (success:bool, prime:char*, prime_1:char*, prime_2:char*, seed:char*)
struct ProvablePrimeGenerationResult{
    bool success_ {};
    BIGNUM *prime_ {};
    BIGNUM *prime_1_ {};
    BIGNUM *prime_2_ {};
    BIGNUM *prime_seed_ {};
    ProvablePrimeGenerationResult(bool success = false, BIGNUM *prime = BN_new(), BIGNUM *prime_1 = BN_new(), BIGNUM *prime_2 = BN_new(), BIGNUM *prime_seed = BN_new());
};

/// @brief This structure holds the data from shawe taylor random prime generation (success:bool, prime:char*, prime_seed:char*, prime_gen_counter:int)
struct ShaweTaylorRandomPrimeResult{
    bool success_ {};
    BIGNUM *prime_ {};
    BIGNUM *prime_seed_ {};
    int prime_gen_counter_ {};
    /// @brief Initializes a shawe taylor random prime result
    /// @param success Whether the shawe generation was successfull
    /// @param prime The prime that was generated
    /// @param prime_seed The next prime seed
    /// @param prime_gen_counter The prime generation counter value after the completion
    ShaweTaylorRandomPrimeResult(bool success = false, BIGNUM* prime = BN_new(), BIGNUM* prime_seed = BN_new(), int prime_gen_counter = 0);
};

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

        /// @brief The hash length being used when generating primes
        int hash_length_ {512};

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
        bool constructTheProvablePrimes();

        /// @brief The method constructs a provable prime that may or may not have additional conditions.
        /// Based on NIST FIPS 186-5 Appendix B.10 "Construct a Provable Prime (Possibly with Conditions) Based on
        /// Contemporaneously Constructed Auxiliary Provable Primes"
        /// @param L The length of the prime
        /// @param N1 The length of the first condition
        /// @param N2 The length of the second condition
        /// @param first_seed_char The first seed as a character array
        /// @return A struct containing a boolean as to whether the method succeeded, a character array of the prime
        /// a character array of the first conditional prime, a character array of the second conditional prime
        /// and a character array of the final seed value for the next prime construction
        ProvablePrimeGenerationResult constructAProvablePrimePotentiallyWithConditions(int L, int N1, int N2, char* first_seed_char);

        /// @brief This method generates a random prime number using the Shawe Taylor methodology.
        /// @param length The bit length for the prime being created
        /// @param input_seed The input seed for the prime being created
        /// @return The result of the prime generation as a struct.
        ShaweTaylorRandomPrimeResult generateRandomPrimeWithShaweTaylor(int length, BIGNUM* input_seed);

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