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

         /// @brief This method performs a bytewise exclusive or operation with another AESDataBlock
        /// @param other The other AESDataBlock to be XORed
        void xorBlock(AESDataBlock other);

        /// @brief This method initializes an AESDataBlock by copying over an unsigned char
        /// @param input 
        /// @param is_hex Whether the string is a hex string, default is true
        AESDataBlock(std::string input, bool is_hex = true);

        /// @brief This method prints out the bytes from the data block
        /// @param with_char_formatting Whether the print statement should be spaced like a character array, default is true
        void print(bool with_char_formatting = false) const;

        /// @brief This method sets the value of a given byte in the data block
        /// @param index The index at which to set the value
        /// @param byte_to_set The new value for the byte
        void setByte(int index, unsigned char byte_to_set);

        /// @brief This method gets the Byte at a given index (constant method)
        /// @param index The index in the AESDataBlock of the byte being retrieved
        /// @return The byte at the given index
        unsigned char getByte(int index) const;

        /// @brief This method overrides the == operator for AESDataBlock objects
        /// @param other The other datablock that is being compared
        /// @return A boolean that is true if all the bytes are the same
        bool operator==(const AESDataBlock &other) const;

        /// @brief This method gets a vector of AESDataBlocks from a single string in hexadecimal form
        /// @param input The hexadecimal string for the input
        /// @return the input as a vector of AES Data Blocks
        static std::vector<AESDataBlock> dataBlocksFromHexString(std::string input);

        /// @brief This method gets the data block as a string of hexadecimal characters
        /// @return The hexadecimal string relating to the datablock
        std::string getString() const;

        /// @brief This method converts a vector of datablocks into a single string of hexadecimal characters
        /// @param input The vector of AESDataBlocks 
        /// @return The string representation of the inputs
        static std::string hexStringFromDataBlocks(std::vector<AESDataBlock> input);

        /// @brief This method shifts the datablock to the right
        /// @param shift_bits The amount to shift the data block in bits
        void operator>>(int shift_bits);

        /// @brief This method shifts the datablock to the left
        /// @param shift_bits The amount to shift the data block in bits
        void operator<<(int shift_bits);

        /// @brief This method gets the segment of a datablock (the segment is in the right most bits of the returned data block, and all other bits are 0)
        /// @param start_bit The start bit of the segment to be retrieved
        /// @param size_bits The number of bits in the segment to be retrieved
        /// @return The segment as the rightmost bits of the datablock
        AESDataBlock getSegment(int start_bit, int size_bits);

        /// @brief This method adds a segment back to a larger data block by XORing it in a given position
        /// @param segment The segment to be added back
        /// @param start_bit The start bit of the segments position once added back
        /// @param size_bits The number of bits in the segment
        void addSegment(AESDataBlock segment, int start_bit, int size_bits);


        /// @brief This method increments the value in the data block
        /// @param inc_amount The value by which to increment the block
        void increment(int inc_amount);

        /// @brief This finds the multiplication in the galois field for use with Galois / Counter Mode
        /// @param X The first number to be multiplied
        /// @param Y The second number to be multiplied
        /// @return An AESDataBlock with the result of the multiplication
        AESDataBlock galoisMultiplication(AESDataBlock const &X, AESDataBlock const &Y);

        bool checkBit(int index) const;

        /// @brief The destructor for AESDataBlock
        ~AESDataBlock();

};

#endif