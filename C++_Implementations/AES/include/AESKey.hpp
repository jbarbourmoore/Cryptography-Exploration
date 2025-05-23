#include "AESConstants.hpp"
#include <vector>
#include <stdio.h>


enum AESKeyTypes{
    AES_KEY_128, AES_KEY_192, AES_KEY_256
};

class AESWord{
    private :
        unsigned char word[4];

    public :
        /// @brief This method initializes an AES key word of 0
        AESWord();

        /// @brief This method initializes an AES key word of a char array value
        AESWord(unsigned char *input);

        /// @brief This method initializes an AES word with the four input values
        /// @param first The first value in the new word
        /// @param second The second value in the new word
        /// @param third The third value in the new word
        /// @param fourth The fourth value in the new word
        AESWord(unsigned char first, unsigned char second, unsigned char third, unsigned char fourth);

        AESWord(AESWord *input);

        void xorWord(AESWord other);

        void rotWord();

        void subWord();

        unsigned char getByte(int index);

        void print();
};

class AESKey{
    public:

        static std::vector<AESWord> keyExpansion(unsigned char *key, AESKeyTypes key_type);

        static int getKeyLength(AESKeyTypes key_type);

        static int getNk(AESKeyTypes key_type);

        static int getNr(AESKeyTypes key_type);

        static int getNb();

        static int getBlockSize();

};

