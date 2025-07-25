#ifndef BigNumHelpers_HPP
#define BigNumHelpers_HPP

#include <openssl/bn.h>
#include <bits/stdc++.h>
#include <vector>

struct PassBigNum{

    /// @brief The intermediate pointer to the big number that is being transfered
    BIGNUM *bn_ {};

    /// @brief Create a transfer struct for a BIGNUM (it performs copy so the origination can clean up)
    /// @param bn The pointer to the bignum being transfers
    PassBigNum(BIGNUM *bn);

    void copyAndClear(BIGNUM *destination_pointer);

    /// @brief This method frees the transfer bignum copy
    void freePassedBN();
};

/// @brief This class holds my helper classes for dealing with OpenSSL BIGNUMs
class BigNumHelpers{
    private:
        static unsigned long long int calculateSquareRoot(unsigned long long int value);
    public:

        /// @brief This method sets the destination pointer to a new bignum in the given context with a copy of the starting pointer
        /// @param destination_pointer The pointer for the new location
        /// @param starting_pointer The pointer for the value to be copied
        /// @param destination_ctx The context to get the copy from
        static void getBNCopyInContext(BIGNUM* destination_pointer, BIGNUM *starting_pointer, BN_CTX *destination_ctx);

        /// @brief This method performs a Byte Wise Xor for two big numbers
        /// @param first_bn The first big number to be XORed
        /// @param second_bn The second big number to be xored
        /// @return The result of the bytewise XOR operation as a big number
        static BIGNUM* xorBigNums(BIGNUM* first_bn, BIGNUM* second_bn);

        /// @brief This method performs a Byte Wise Xor for two big numbers
        /// @param first_bn The first big number to be XORed
        /// @param second_bn The second big number to be xored
        /// @return The result of the bytewise XOR operation as a big number
        static PassBigNum xorBigNums(PassBigNum first_bn, PassBigNum second_bn);

        /// @brief This method performs a Byte Wise Xor for two big numbers
        /// @param result_pointer The pointer to the location the result shall be stored
        /// @param first_bn The first big number to be XORed
        /// @param second_bn The second big number to be xored
        static void xorBigNums(BIGNUM* result_pointer, BIGNUM* first_bn, BIGNUM* second_bn);

        /// @brief This method finds the SHA224 hash of a given BIGNUM
        /// @param result The pointer to the BIGNUM where the hash digest will be placed
        /// @param input_bn The pointer to the BIGNUM to be hashed
        static void sha224BigNum(BIGNUM* result, BIGNUM* input_bn);

        /// @brief This method finds the SHA256 hash of a given BIGNUM
        /// @param result The pointer to the BIGNUM where the hash digest will be placed
        /// @param input_bn The pointer to the BIGNUM to be hashed
        static void sha256BigNum(BIGNUM* result, BIGNUM* input_bn);

        /// @brief This method finds the SHA384 hash of a given BIGNUM
        /// @param result The pointer to the BIGNUM where the hash digest will be placed
        /// @param input_bn The pointer to the BIGNUM to be hashed
        static void sha384BigNum(BIGNUM* result, BIGNUM* input_bn);

        /// @brief This method finds the SHA512 hash of a given BIGNUM
        /// @param result The pointer to the BIGNUM where the hash digest will be placed
        /// @param input_bn The pointer to the BIGNUM to be hashed
        static void sha512BigNum(BIGNUM* result, BIGNUM* input_bn);

        /// @brief This method finds the SHA3 224 hash of a given BIGNUM
        /// @param result The pointer to the BIGNUM where the hash digest will be placed
        /// @param input_bn The pointer to the BIGNUM to be hashed
        static void sha3_224BigNum(BIGNUM* result, BIGNUM* input_bn);

        /// @brief This method finds the SHA3 256 hash of a given BIGNUM
        /// @param result The pointer to the BIGNUM where the hash digest will be placed
        /// @param input_bn The pointer to the BIGNUM to be hashed
        static void sha3_256BigNum(BIGNUM* result, BIGNUM* input_bn);

        /// @brief This method finds the SHA3 384 hash of a given BIGNUM
        /// @param result The pointer to the BIGNUM where the hash digest will be placed
        /// @param input_bn The pointer to the BIGNUM to be hashed
        static void sha3_384BigNum(BIGNUM* result, BIGNUM* input_bn);

        /// @brief This method finds the SHA3-512 hash of a given BIGNUM
        /// @param result The pointer to the BIGNUM where the hash digest will be placed
        /// @param input_bn The pointer to the BIGNUM to be hashed
        static void sha3_512BigNum(BIGNUM* result, BIGNUM* input_bn);

        /// @brief This method finds the SHAKE224 xof of a given BIGNUM
        /// @param result The pointer to the BIGNUM where the hash digest will be placed
        /// @param input_bn The pointer to the BIGNUM to be hashed
        static void shake128BigNum(BIGNUM* result, BIGNUM* input_bn, int digest_length);

        /// @brief This method finds the SHAKE256 xof of a given BIGNUM
        /// @param result The pointer to the BIGNUM where the hash digest will be placed
        /// @param input_bn The pointer to the BIGNUM to be hashed
        static void shake256BigNum(BIGNUM* result, BIGNUM* input_bn, int digest_length);

        /// @brief This method calculates the gcd of a value minus one and a second value
        /// @param result The pointer for the result of the BN of the result
        /// @param first_value The value from which we subtract one
        /// @param second_value The other value for which we are calculating the gcd
        static void  gcdValueMinusOneSecondValue(BIGNUM* result, BIGNUM* first_value, BIGNUM* second_value);

        /// @brief This method find all the prime numbers less than the value passed to it
        /// @param maximum_value The maximum value for any prime number found
        /// @return The vector containing all of the prime numbers
        static std::vector<unsigned long long int> primeSieve(BIGNUM* maximum_bignum);

        /// @brief This method find all the prime numbers less than the value passed to it
        /// @param max_val The maximum value for any prime number found
        /// @return The vector containing all of the prime numbers
        static std::vector<unsigned long long int> primeSieve(unsigned long long int max_val);

        /// @brief This method converts a bignumber into a long long if it is small enough
        /// @param input The bignum to be converted
        /// @return The bignum as an unsigned long long or 0 if the number is too large
        static unsigned long long int bnToUnsignedLongLong(BIGNUM*input);

        static int trialDivision(BIGNUM* candidate_prime_bn);

};
#endif