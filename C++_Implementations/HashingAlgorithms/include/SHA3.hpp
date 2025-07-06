#ifndef SHA3_HPP
#define SHA3_HPP

#include "SHA.hpp"
#include <array>
#include <bitset>
#include <string>
#include <cmath>



class SHA3_State {

    private :
        /// @brief The w value (dimension of the z bit set)
        int w_ = 64;

        /// @brief This method converts a single bitset to a state consisting of a 5 x 5 x 64 bit array
        /// @param bits_input 
        void bitsetToState(std::bitset<1600> bits_input);

        /// @brief The state array 5 x 5 x 64 bits
        std::array<std::array<std::bitset<64>, 5>, 5> a_;

    public :
         /// @brief This method calculated the positive modulus value 
        /// @param val The value of which the modulus is being calculated
        /// @param modulus The modulus
        /// @return The modulus of the given value as an int
        static int mod(int val, int modulus);

        /// @brief This method initializes a SHA3 state with a value of 0
        SHA3_State();

        /// @brief This method initializes a SHA3 state from a single dimension bitset
        /// @param bitset_input The single dimension bitset to be converted into the state array
        SHA3_State(std::bitset<1600> bitset_input);

        /// @brief This method initializes a SHA3 state from a hexadecimal string
        /// @param hex_input The hexadecimal input converted into a SHA3_state object
        SHA3_State(std::string hex_input);

        /// @brief The method sets a single bit within the state array 
        /// @param value The value to set the bit 
        /// @param x The x coordinate of the bit to be set
        /// @param y The y coordinate of the bit to be set
        /// @param z The z coordinate of the bit to be set
        void setBit(bool value, int x, int y, int z);

        /// @brief This method checks the current value of a bit within the state array
        /// @param x The x coordinate of the bit to be set
        /// @param y The y coordinate of the bit to be set
        /// @param z The z coordinate of the bit to be set
        /// @return The current value of the bit
        bool checkBit(int x, int y, int z);

        /// @brief This method prints the bits of the state array to the console 
        void printBits();

        /// @brief This method prints the value of the state array to the console as hexadecimal
        void printHex();

        /// @brief This method gets the value of the state array as a single bitset
        /// @return The bitset corresponding to the value of the state array
        std::bitset<1600> getValueAsBitset();

        /// @brief This method gets the value of the state array as a hexadecimal string
        /// @return The hexadecimal string corresponding to the value of the state array
        std::string getValueAsHex();

        /// @brief This method gets a single row from the state array
        /// @param y The y coordinate of the row
        /// @param z The z coordinate of the row
        /// @return The row of x bits at the y and z coordinate
        std::bitset<5> getRow(int y, int z);

        /// @brief This method sets a single row from the state array
        /// @param y The y coordinate of the row
        /// @param z The z coordinate of the row
        /// @param input_row The new row of x bits at the y and z coordinate
        void setRow(int y, int z, std::bitset<5> input_row);

        /// @brief This method gets a single column from the state array
        /// @param x The x coordinate of the column
        /// @param z The z coordinate of the column
        /// @return The column of y bits at the x and z coordinate
        std::bitset<5> getColumn(int x, int z);

        /// @brief This method sets a single column from the state array
        /// @param z The z coordinate of the column
        /// @param z The z coordinate of the column
        /// @param input_column The new column of x bits at the x and z coordinate
        void setColumn(int x, int z, std::bitset<5> input_column);

        /// @brief This method gets a single lane from the state array
        /// @param x The x coordinate of the lane
        /// @param z The y coordinate of the lane
        /// @return The lane of z bits at the x and y coordinate
        std::bitset<64> getLane(int x, int y);

        /// @brief This method sets a single lane from the state array
        /// @param z The z coordinate of the lane
        /// @param z The y coordinate of the lane
        /// @param input_lane The new lane of z bits at the x and y coordinate
        void setLane(int x, int y, std::bitset<64> input_lane);

        void theta();

        void rho();

        void pi();

        void chi();

        void iota(int ir);

        void round(int ir);
};

class SHA3 : public SHA{

    private :

        /// @brief the number of bits in each internal block to be processed
        static const int block_bit_size_ = 1600;

        /// @brief The number of hexadecimal charaters in each internal block to be processed
        static const int block_hex_size_ = 400;

        /// @brief This method pads a binary message and breaks it into appropriate blocks for internal processing
        /// @param bit_message The binary message to be hashed
        /// @return The list of all binary blocks to be processed
        static std::vector<std::bitset<1600>> padBitMessage(std::vector<bool> bit_message, int digest_length);

        static std::vector<bool> sponge(std::vector<std::bitset<1600>> P);

        static void keccak_f_1600();
        // /// @brief This method pads a hexadecimal message and breaks it into appropriate blocks for internal processing
        // /// @param hex_message The hexadecimal message to be hashed
        // /// @return The list of all hexadecimal blocks to be processed
        // std::vector<std::string> padHexMessage(std::string hex_message, int digest_length);

};

#endif