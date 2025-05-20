#ifndef SHA_HPP
#define SHA_HPP

#include <string.h>
#include <bits/stdc++.h>
#include <sys/types.h>
#include <cassert>
#include <array>
#include <vector>

using namespace std;

class SHA{
    protected :

        /// @brief The hash algorithm's block size in bits (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        const int BLOCK_SIZE = 512;
        /// @brief The hash algorithm's word size in bits (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        const int WORD_SIZE = 32;
        /// @brief The hash algorithm's message digest size in bits (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        const int MESSAGE_DIGEST_SIZE = 256;
        /// @brief The hash algorithm's maximum message size in bits, that is the size < 2 ** var (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        const int MAX_MESSAGE_SIZE_POWER_OF_2 = 64;
        /// @brief The number of bits available in the final block
        const int FINAL_BLOCK_CAPACITY = 448;
        /// @brief The total number of iterations per block
        const int ITERATION_COUNT = 64;

    public :

        /// @brief This method creates a SHA Hash Digest of the input hex string
        /// @param input_hex The hex string that is to be hashed
        /// @return The hex string of the hash digest
        virtual string hashHexString(string input_hex) = 0;

        /// @brief This method creates a SHA Hash Digest of the input string
        /// @param input_hex The string that is to be hashed
        /// @return The hex string of the hash digest
        virtual string hashString(string input_string) = 0;

        // /// @brief This method creates a SHA Hash Digest of the input bit string
        // /// @param input_hex The bit string that is to be hashed
        // /// @return The hex string of the hash digest
        // virtual string hashBitString(string input_bits) = 0;
};

#endif