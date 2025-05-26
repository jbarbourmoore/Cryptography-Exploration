#ifndef GCMBlock_HPP
#define GCMBlock_HPP

#include "AES.hpp"
#include "inttypes.h"

class GCMBlock{

    private :
        unsigned __int128 block;

    public:
        GCMBlock();

        GCMBlock(AESDataBlock input);

        GCMBlock(GCMBlock const &input);

        GCMBlock(std::string input);

        GCMBlock(unsigned __int128 input);

        /// @brief This method performs the multiplication in the galois field of two GCMBlocks. 
        /// According to Section 2.5, Algorithm 1 of https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf 
        /// @param X The first block to be multiplied
        /// @param Y The second block to be multiplied 
        /// @return The block that is the result of the multiplication
        static GCMBlock galoisMultiplication(GCMBlock const &X, GCMBlock const &Y);

        /// @brief This method performs a right shift on the GCM block
        /// @param shift_bits The number of bits to shift the GCM block
        void operator>>(int shift_bits);

        /// @brief This method performs a left shift on the GCM block
        /// @param shift_bits The number of bits to shift the GCM block
        void operator<<(int shift_bits);

        /// @brief This method checks whether two blocks contain the same value
        /// @param other The GCMBlock which this one is being compared to
        /// @return true if the blocks are the same value
        bool operator==(GCMBlock const &other) const;

        /// @brief This method increments the blcok by an integer value
        /// @param increment_value The value by which we are incrementing the block
        void increment(int increment_value);

        /// @brief This method prints the block to the console as a hex string
        void print() const;

        /// @brief This method converts the blcok into a hex string
        /// @return The hex string containing the value of the block
        std::string getHexString() const;

        /// @brief This method checks whether a specific bit is set
        /// @param index The index of the bit
        /// @return True if the bit is currently 1
        bool checkBit(int index) const;

        /// @brief This method performs a XOR operation on two blocks
        /// @param other The other block being XORed
        /// @return The result of the XOR operation as its own block
        GCMBlock operator^(GCMBlock const &other) const;
};


#endif