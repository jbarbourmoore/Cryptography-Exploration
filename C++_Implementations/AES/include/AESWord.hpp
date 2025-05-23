#ifndef AESWord_HPP
#define AESWord_HPP

#include "AESConstants.hpp"

#include <cstdio>

class AESWord{
    private :
        /// @brief The word stored as an unsigned character array with 4 elements
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

        /// @brief This method is a copy instantiator
        /// @param input The AES word to be copied into the new word
        AESWord(const AESWord &input);

        /// @brief This method performs a bytewise exclusive or operation with another AESWord
        /// @param other The other AESWord to be XORed
        void xorWord(AESWord other);

        /// @brief This method performs the rotWord function as described in NIST FIPS 197
        void rotWord();

        /// @brief This method performs the subWord function as descrided in NIST FIPS 197
        void subWord();

        /// @brief This method gets the Byte at a given index (constant method)
        /// @param index The index in the AESWord of the byte being retrieved
        /// @return The byte at the given index
        unsigned char getByte(int index) const;

        /// @brief This method prints the word to the command line
        void print() const;

        /// @brief This method overrides the == operator for AESWord objects
        /// @param other The other word that is being compared
        /// @return A boolean that is true if all the bytes are the same
        bool operator==(const AESWord &other) const;
};

#endif