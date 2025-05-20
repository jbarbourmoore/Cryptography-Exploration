#ifndef CreateHashDigest_HPP
#define CreateHashDigest_HPP

#include <string.h>
#include <bits/stdc++.h>
#include "SHA_32bit.hpp"
#include "SHA_64bit.hpp"

using namespace std;

enum HashType{
    SHA1_DIGEST, SHA256_DIGEST, SHA224_DIGEST, SHA512_DIGEST, SHA384_DIGEST, SHA512_224_DIGEST, SHA512_256_DIGEST
};

class CreateHashDigest {
    public :
        /// @brief This method gets the digest length associated with a given hash type
        /// @param hash_type Which hash typ you are retrieving the length for
        /// @return The digest length in bits
        static int getDigestLength(HashType hash_type);

        /// @brief This method gets the hash digest as a hex string 
        /// @param input_string The string that you are hashing
        /// @param hash_type The type of hash you are performing
        /// @return The digest as a hexadecimal string
        static string fromString(string input_string, HashType hash_type);

        /// @brief This method gets the hash digest as a hex string 
        /// @param input_string The string that you are hashing
        /// @param hash_type The type of hash you are performing
        /// @return The digest as a hexadecimal string
        static string fromHexString(string input_hex, HashType hash_type);

        // static string fromBitString(string input_bit, HashType hash_type);
};

#endif