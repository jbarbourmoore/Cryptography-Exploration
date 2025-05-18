#ifndef RSAKeyGeneration_HPP
#define RSAKeyGeneration_HPP

#include <openssl/bn.h>
#include <string.h>
#include <cassert>
#include "BigNumHelpers.hpp"
#include "RSAPrivateKey.hpp"
#include "RSAPublicKey.hpp"

/// @brief This structure holds the result from generating RSA public and private keys
struct RSAKeyGenerationResult{

    /// @brief Whether the key generation was a success
    bool success_ {};

    /// @brief The private key that was generated
    RSAPrivateKey private_key_ {};

    /// @brief The public key that was generated
    RSAPublicKey public_key_ {};

    /// @brief The length of the key in bits ('nlen')
    int key_length_ {};

    /// @brief Initializes a key generation result
    /// @param success Whether the key generation was successful
    /// @param private_key The private key that was generated
    /// @param public_key The public key that was generated
    /// @param key_length the length of the key in bits
    RSAKeyGenerationResult(bool success = false, RSAPrivateKey private_key = RSAPrivateKey(), RSAPublicKey public_key = RSAPublicKey(), int key_length = 2048);

};

struct ConstructPandQResult{
    bool success_ {};

    /// @brief The context used for the p & q construction result
    BN_CTX *result_ctx_ {};

    /// @brief The big number containing the first prime 'p'
    BIGNUM *p_ {};

    /// @brief The big number containing the first prime 'q'
    BIGNUM *q_ {};

    /// @brief Initializes a result from generating 'p' and 'q
    /// @param success Whether the prime construction was successful, default is false
    /// @param p The prime 'p'
    /// @param q The prime 'q'
    ConstructPandQResult(bool success, BIGNUM *p, BIGNUM *q);

    /// @brief This method initializes a false result
    ConstructPandQResult();

    /// @brief This method frees the BIGNUMs contained by this stucture
    void freeResult();
};

/// @brief This structure holds the data from construction of a provable prime (success:bool, prime:char*, prime_1:char*, prime_2:char*, seed:char*)
struct ProvablePrimeGenerationResult{

    /// @brief Whether the provable prime generation was a success
    bool success_ {};

    /// @brief The generated prime
    BIGNUM *prime_ {};

    /// @brief The first auxillary prime
    BIGNUM *prime_1_ {};

    /// @brief The second auxillary prime
    BIGNUM *prime_2_ {};

    /// @brief The next prime seed
    BIGNUM *prime_seed_ {};

    /// @brief Initializes a provable prime generation result
    /// @param success optional - Whether the provable prime generation was successful, default is false
    /// @param prime optional - The prime that was generated, default is new
    /// @param prime_1 optional - The first auxillary prime, default is new
    /// @param prime_2 optional - The second auxillary prime, default is new
    /// @param prime_seed optional - The next prime seed, default is new
    ProvablePrimeGenerationResult(bool success, BIGNUM *prime, BIGNUM *prime_1, BIGNUM *prime_2, BIGNUM *prime_seed);

    /// @brief This method initializes a false result
    ProvablePrimeGenerationResult();

    void freeResult();
};

/// @brief This structure holds the data from construction of a probable prime (success:bool, prime:BIGNUM*, X:BIGNUM*)
struct ProbablePrimeGenerationWithAuxResult{

    /// @brief Whether the probable prime generation was a success
    bool success_ {};

    /// @brief The generated prime
    BIGNUM *prime_ {};

    /// @brief The X value used to create the prime
    BIGNUM *X_ {};

    /// @brief Initializes a probable prime generation result
    /// @param success Whether the probable prime generation was successful
    /// @param prime The prime that was generated
    /// @param X The X value used in the generation of the prime
    ProbablePrimeGenerationWithAuxResult(bool success, BIGNUM *prime, BIGNUM *X);

    /// @brief This method initializes a false result
    ProbablePrimeGenerationWithAuxResult();

    void freeResult();
};

/// @brief This structure holds the data from shawe taylor random prime generation (success:bool, prime:char*, prime_seed:char*, prime_gen_counter:int)
struct ShaweTaylorRandomPrimeResult{

    /// @brief Whether the random prime generation was successful
    bool success_ {};

    /// @brief The generated prime
    BIGNUM *prime_ {};

    /// @brief  The next prime seed value
    BIGNUM *prime_seed_ {};

    /// @brief The current count of prime gen counter
    int prime_gen_counter_ {};
    /// @brief Initializes a shawe taylor random prime result
    /// @param success optional - Whether the shawe generation was successful, default is false
    /// @param prime optional - The prime that was generated, default is new
    /// @param prime_seed optional - The next prime seed, default is new
    /// @param prime_gen_counter optional - The prime generation counter value after the completion, default is new
    ShaweTaylorRandomPrimeResult(bool success, BIGNUM* prime, BIGNUM* prime_seed, int prime_gen_counter);

    /// @brief This method initializes a false result
    ShaweTaylorRandomPrimeResult();

    void freeResult();
};

/// @brief This class contains the variables and methods for an RSA Private Key
class RSAKeyGeneration{

    private:
        /// @brief The minimum value for e (the public exponent)
        BIGNUM *e_min_;

        /// @brief The maximum value for e (the public exponent)
        BIGNUM *e_max_;

        /// @brief The minimum difference between 'p' and 'q'
        BIGNUM *min_pq_diff_;

        /// @brief The minimum value for both 'p' and 'q'
        BIGNUM *min_prime_value_;

        /// @brief the key length in bits
        int keylength_ {2048};

        /// @brief The hash length being used when generating primes
        int hash_length_ {512};

        /// @brief The BN CTX to be used in the calculations for this rsa key generation
        BN_CTX *context_;

        /// @brief This method sets the parameters for e
        void setEParameters();

        /// @brief This method sets the minimum difference between 'p' and 'q'
        void setMinPQDiff();

        /// @brief This method sets the minimum value for both 'p' and 'q'
        void setMinPrimeValue();

        /// @brief This method generates a seed value to be used in generating provable primes
        /// Based on Nist Fips 186-5 Appendix A.1.2.1 "Get the seed"
        void generateRandomSeed(BIGNUM* seed);

        /// @brief This method generates a random public exponenent to be used in the RSA keys
        /// @parameter The pointer to the public exponent, 'e', as a BIGNUM
        void generateRandomE(BIGNUM *e);

        /// @brief This method generates the probable primes 'p' and 'q' to be used in the RSA keys
        /// Based on Nist Fips 186-5 A.1.3 "Generation of Random Primes that are Probably Prime"
        /// @param a Optional - The restriction for p mod 8, default is -1 (which means no restriction in this implementation)
        /// @param b Optional - The restriction for q mod 8, default is -1 (which means no restriction in this implementation)
        /// @param e The public exponent
        /// @return A ConstructPandQResult containing, success p and q.
        ConstructPandQResult constructTheProbablePrimes(int a = -1, int b = -1, BIGNUM *e = BN_new());

        /// @brief This method generates the probable prime to be used in the RSA keys
        /// Based on Nist Fips 186-5 B.9 "Compute a Probable Prime Factor Based on Auxiliary Primes"
        /// @param r1 The first auxillary prime to be used when constructing the probable prime
        /// @param r2 The second auxillary prime to be used when constructing the probable prime
        /// @param e The public exponent
        /// @param c Optional - The restriction for the prime mod 8, default is -1 (which means no restriction in this implementation)
        /// @return A ConstructPandQResult containing, success p and q.
        ProbablePrimeGenerationWithAuxResult constructAProbablePrimeWithAux( BIGNUM *r1, BIGNUM *r2, BIGNUM *e, int c = -1);

        /// @brief This method generates the probable primes 'p' and 'q' to be used in the RSA keys
        /// Based on Nist Fips 186-5 A.1.5 "Generation of Probable Primes with Conditions Based on Auxiliary Provable Primes "
        /// @param a Optional - The restriction for p mod 8, default is -1 (which means no restriction in this implementation)
        /// @param b Optional - The restriction for q mod 8, default is -1 (which means no restriction in this implementation)
        /// @param bitlen1 Optional - The bit length for p1, default is 200
        /// @param bitlen2 Optional - The bit length for p2, default is 200
        /// @param bitlen3 Optional - The bit length for q1, default is 200
        /// @param bitlen4 Optional - The bit length for q2, default is 200
        /// @param e The public exponent
        /// @return A ConstructPandQResult containing, success p and q.
        ConstructPandQResult constructTheProbablePrimesWithProvableAux(int a = -1, int b = -1, int bitlen1 = 200, int bitlen2 = 200, int bitlen3 = 200, int bitlen4 = 200, BIGNUM *seed = BN_new(), BIGNUM *e = BN_new());

        /// @brief This method generates the probable primes 'p' and 'q' to be used in the RSA keys
        /// Based on Nist Fips 186-5 A.1.6 "Generation of Probable Primes with Conditions Based on Auxiliary Probable Primes "
        /// @param a Optional - The restriction for p mod 8, default is -1 (which means no restriction in this implementation)
        /// @param b Optional - The restriction for q mod 8, default is -1 (which means no restriction in this implementation)
        /// @param bitlen1 Optional - The bit length for p1, default is 200
        /// @param bitlen2 Optional - The bit length for p2, default is 200
        /// @param bitlen3 Optional - The bit length for q1, default is 200
        /// @param bitlen4 Optional - The bit length for q2, default is 200
        /// @param e The public exponent
        /// @return A ConstructPandQResult containing, success p and q.
        ConstructPandQResult constructTheProbablePrimesWithProbableAux(int a = -1, int b = -1, int bitlen1 = 200, int bitlen2 = 200, int bitlen3 = 200, int bitlen4 = 200, BIGNUM *e = BN_new());

        /// @brief This method generates the provable primes 'p' and 'q' to be used in the RSA keys
        /// Based on Nist Fips 186-5 Appendix A.1.2.2 "Construction of the Provable Primes p and q"
        ConstructPandQResult constructTheProvablePrimes(BIGNUM *seed, BIGNUM *e);

        /// @brief This method generates the provable primes 'p' and 'q' to be used in the RSA keys
        /// Based on Nist Fips 186-5 Appendix A.1.2.2 "Construction of the Provable Primes p and q"
        /// @param N1 The length of the first condition
        /// @param N2 The length of the second condition
        ConstructPandQResult constructTheProvablePrimesWithAuxillary(BIGNUM *seed, int N1, int N2, BIGNUM *e);

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
        ProvablePrimeGenerationResult constructAProvablePrimePotentiallyWithConditions(int L, int N1, int N2, BIGNUM *first_seed, BIGNUM *e);

        /// @brief This method generates a random prime number using the Shawe Taylor methodology if length < 33
        /// @param length The bit length for the prime being created
        /// @param input_seed The input seed for the prime being created
        /// @return The result of the prime generation as a struct.
        ShaweTaylorRandomPrimeResult shaweTaylorShort(int length, PassBigNum input_seed);

        /// @brief This method generates a random prime number using the Shawe Taylor methodology.
        /// @param length The bit length for the prime being created
        /// @param input_seed The input seed for the prime being created
        /// @return The result of the prime generation as a struct.
        ShaweTaylorRandomPrimeResult generateRandomPrimeWithShaweTaylor(int length, PassBigNum input_seed);

        /// @brief This method calculated the private exponent 'd'
        /// @param d The pointer for the public exponent, d;
        /// @param e The public exponent 'e'
        /// @param p The first prime 'p'
        /// @param q The second prime 'q'
        /// @return 'd' The private exponent for the RSA keys
        void generatePrivateExponent(BIGNUM *d, BIGNUM *e, BIGNUM *p, BIGNUM *q);

    public:

        /// @brief Instantiates RSAKeyGeneration with a given keylength in bits
        /// @param keylength The key length in bits to be used for the RSA Key Generation, default is 2048
        RSAKeyGeneration(int keylength = 2048);

        /// @brief This method generates RSA keys based on provable primes.
        /// Based on Nist Fips 186-5 Appendix A.1.2 "Generation of Random Primes that are Provably Prime"
        /// @param use_key_quintuple_form Optional - Whether or not the generated private key should be in quintuple form (default is true)
        RSAKeyGenerationResult generateRSAKeysUsingProvablePrimes(bool use_key_quintuple_form = true);

        /// @brief This method generates RSA keys based on provable primes.
        /// Based on Nist Fips 186-5 A.1.3 "Generation of Random Primes that are Probably Prime"
        /// @param a Optional - The restriction for p mod 8, default is -1 (which means no restriction in this implementation)
        /// @param b Optional - The restriction for q mod 8, default is -1 (which means no restriction in this implementation)
        /// @param use_key_quintuple_form Optional - Whether or not the generated private key should be in quintuple form (default is true)
        /// @return The result of the key generation consisting of a public key, private key and whether it succeeded
        RSAKeyGenerationResult generateRSAKeysUsingProbablePrimes(int a = -1, int b = -1, bool use_key_quintuple_form = true);

        /// @brief This method generates RSA keys based on provable primes with provable auxillary primes.
        /// Based on Nist Fips 186-5 A.1.5 "Generation of Probable Primes with Conditions Based on Auxiliary Provable Primes"
        /// @param a Optional - The restriction for p mod 8, default is -1 (which means no restriction in this implementation)
        /// @param b Optional - The restriction for q mod 8, default is -1 (which means no restriction in this implementation)
        /// @param bitlen1 Optional - The bit length for p1, default is 200
        /// @param bitlen2 Optional - The bit length for p2, default is 200
        /// @param bitlen3 Optional - The bit length for q1, default is 200
        /// @param bitlen4 Optional - The bit length for q2, default is 200
        /// @param use_key_quintuple_form Optional - Whether or not the generated private key should be in quintuple form (default is true)
        /// @return The result of the key generation consisting of a public key, private key and whether it succeeded
        RSAKeyGenerationResult generateRSAKeysUsingProbablePrimesWithProvableAux(int a = -1, int b = -1, int bitlen1 = 200, int bitlen2 = 200, int bitlen3 = 200, int bitlen4 = 200, bool use_key_quintuple_form = true);

        /// @brief This method generates RSA keys based on provable primes with probable auxillary primes.
        /// Based on Nist Fips 186-5 A.1.6 "Generation of Probable Primes with Conditions Based on Auxiliary Probable Primes"
        /// @param a Optional - The restriction for p mod 8, default is -1 (which means no restriction in this implementation)
        /// @param b Optional - The restriction for q mod 8, default is -1 (which means no restriction in this implementation)
        /// @param bitlen1 Optional - The bit length for p1, default is 200
        /// @param bitlen2 Optional - The bit length for p2, default is 200
        /// @param bitlen3 Optional - The bit length for q1, default is 200
        /// @param bitlen4 Optional - The bit length for q2, default is 200
        /// @param use_key_quintuple_form Optional - Whether or not the generated private key should be in quintuple form (default is true)
        /// @return The result of the key generation consisting of a public key, private key and whether it succeeded
        RSAKeyGenerationResult generateRSAKeysUsingProbablePrimesWithProbableAux(int a = -1, int b = -1, int bitlen1 = 200, int bitlen2 = 200, int bitlen3 = 200, int bitlen4 = 200, bool use_key_quintuple_form = true);

        /// @brief This method generates RSA keys based on provable primes.
        /// @param N1 The length of the first auxillary prime in bits
        /// @param N2 The length of the second auxillary prime in bits 
        /// @param use_key_quintuple_form Optional - Whether or not the generated private key should be in quintuple form (default is true)
        /// @return The RSA Key Generation Result with both the public and private keys
        RSAKeyGenerationResult generateRSAKeysUsingProvablePrimesWithAuxPrimes(int N1, int N2, bool use_key_quintuple_form);

        /// @brief This method returns the security strength for the RSA Key Generation basec on the key length
        /// @return The security strength
        int getSecurityStrength();

        /// @brief This method returns the key length for the RSA Key Generation
        /// @return The key length in bits
        int getKeyLength();

        /// @brief This method returns the bit length for each large prime for the RSA Key Generation
        /// @return The prime length in bits
        int getPrimeLength();

        /// @brief This method end the key generation and frees the variables used
        void freeKeyGeneration();

        void generatePseudoRandomNumber(BIGNUM* result, int iteration_count, BIGNUM* seed);
};

#endif