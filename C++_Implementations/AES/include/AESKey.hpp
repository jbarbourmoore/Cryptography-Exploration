#ifndef AESKey_HPP
#define AESKey_HPP

#include "AESConstants.hpp"
#include "AESWord.hpp"
#include <vector>
#include <stdio.h>


enum AESKeyTypes{
    AES_KEY_128, AES_KEY_192, AES_KEY_256
};

class AESKey{
    public:

        static std::vector<AESWord> keyExpansion(unsigned char *key, AESKeyTypes key_type);

        static int getKeyLength(AESKeyTypes key_type);

        static int getNk(AESKeyTypes key_type);

        static int getNr(AESKeyTypes key_type);

        static int getNb();

        static int getBlockSize();

        static bool compareWordAtIndex(std::vector<AESWord> expanded_key, AESWord word_to_compare, int index);

};


#endif