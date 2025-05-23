#ifndef AESKey_HPP
#define AESKey_HPP

#include "AESConstants.hpp"
#include "AESWord.hpp"
#include <vector>
#include <array>
#include <stdio.h>


enum AESKeyTypes{
    AES_KEY_128, AES_KEY_192, AES_KEY_256
};

class AESKey{
    public:

        /// @brief This method performs the key expansion as defined in NIST FIPS 197 Section 5.2 "KEYEXPANSION()"
        /// @param key The key that is to be expanded
        /// @param key_type Which AES variant the key is for
        /// @return The expanded key
        static std::vector<AESWord> keyExpansion(unsigned char *key, AESKeyTypes key_type);

        /// @brief This method gets the key length in bits
        /// @param key_type Which AES variant is being queried
        /// @return The key length in bits
        static int getKeyLength(AESKeyTypes key_type);

        /// @brief This method gets the value for Nk
        /// @param key_type Which AES variant is being queried
        /// @return The Nk value
        static int getNk(AESKeyTypes key_type);

        /// @brief This method gets the value for Nr
        /// @param key_type Which AES variant is being queried
        /// @return The number of rounds to be performed
        static int getNr(AESKeyTypes key_type);

        /// @brief This method gets the value for Nb
        /// @return The number of blocks
        static int getNb();

        /// @brief This method gets the block size in bits
        /// @return The internal block size in bits
        static int getBlockSize();
};


#endif