#ifndef BigNumHelpers_HPP
#define BigNumHelpers_HPP

#include <openssl/bn.h>
#include <bits/stdc++.h>
#include <openssl/evp.h>

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
};
#endif