#ifndef AESDataBlock_HPP
#define AESDataBlock_HPP

#include <vector>
#include <cstdio>
#include <string>

class AESDataBlock {
    private :
        /// @brief The 16 byte set of data 
        unsigned char data_block[16];

    public :

        /// @brief The number of bytes in an AESDataBlock
        static const int byte_length = 16;

        /// @brief This method instantiates a data block with all bytes set to zero
        AESDataBlock();

        /// @brief This method is the copy initializes
        /// @param input The AESDataBlock to be copied over
        AESDataBlock(const AESDataBlock &input);

        /// @brief This method initializes an AESDataBlock by copying over an unsigned char
        /// @param input 
        AESDataBlock(unsigned char* input);

        /// @brief This method initializes an AESDataBlock by copying over an unsigned char
        /// @param input 

        /// @brief This method initializes an AESDataBlock by copying over an unsigned char
        /// @param input 
        /// @param is_hex Whether the string is a hex string, default is true
        AESDataBlock(std::string input, bool is_hex = true);

        /// @brief This method prints out the bytes from the data block
        /// @param with_char_formatting Whether the print statement should be spaced like a character array, default is true
        void print(bool with_char_formatting = true) const;

        void setByte(int index, unsigned char byte_to_set);

        /// @brief This method gets the Byte at a given index (constant method)
        /// @param index The index in the AESDataBlock of the byte being retrieved
        /// @return The byte at the given index
        unsigned char getByte(int index) const;

        /// @brief This method overrides the == operator for AESDataBlock objects
        /// @param other The other datablock that is being compared
        /// @return A boolean that is true if all the bytes are the same
        bool operator==(const AESDataBlock &other) const;
};

#endif