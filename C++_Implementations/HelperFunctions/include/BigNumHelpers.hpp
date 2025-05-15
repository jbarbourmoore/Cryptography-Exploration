#ifndef BigNumHelpers_HPP
#define BigNumHelpers_HPP

#include <openssl/bn.h>
#include <bits/stdc++.h>
#include <openssl/evp.h>
#include <vector>
/// @brief This class holds my helper classes for dealing with OpenSSL BIGNUMs
class BigNumHelpers{
    public:
        /// @brief This method performs a Byte Wise Xor for two big numbers
        /// @param first_bn The first big number to be XORed
        /// @param second_bn The second big number to be xored
        /// @return The result of the bytewise XOR operation as a big number
        static BIGNUM* xorBigNums(BIGNUM* first_bn, BIGNUM* second_bn);

        /// @brief This method finds the SHA224 hash of a given BIGNUM
        /// @param bignum_to_hash This big number to be hashed
        /// @return The resulting SHA224 hash digest as a big number
        static BIGNUM* sha224BigNum(BIGNUM* bignum_to_hash);

        /// @brief This method finds the SHA256 hash of a given BIGNUM
        /// @param bignum_to_hash This big number to be hashed
        /// @return The resulting SHA256 hash digest as a big number
        static BIGNUM* sha256BigNum(BIGNUM* bignum_to_hash);

        /// @brief This method finds the SHA384 hash of a given BIGNUM
        /// @param bignum_to_hash This big number to be hashed
        /// @return The resulting SHA384 hash digest as a big number
        static BIGNUM* sha384BigNum(BIGNUM* bignum_to_hash);

        /// @brief This method finds the SHA512 hash of a given BIGNUM
        /// @param bignum_to_hash This big number to be hashed
        /// @return The resulting SHA512 hash digest as a big number
        static BIGNUM* sha512BigNum(BIGNUM* bignum_to_hash);

        /// @brief This method calculates the gcd of a value minus one and a second value
        /// @param first_value The value from which we shall subtract one
        /// @param second_value The second value
        /// @return The greatest common denominator as a BIGNUM
        static BIGNUM* gcdValueMinusOneSecondValue(BIGNUM* first_value, BIGNUM* second_value);

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

};
#endif