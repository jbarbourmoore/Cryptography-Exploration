#ifndef AESState_HPP
#define AESState_HPP

#include "AESConstants.hpp"
#include "AESWord.hpp"

#include <cstdio>
#include <array>

struct AESState{

    private :
        /// @brief The state stored as an unsigned character array of 16 items
        unsigned char s[16];

    public :
        /// @brief This method initializes an AES state of 0
        AESState();

        /// @brief This method initializes an AES State with a copy of s_input
        /// @param s_input The unsigned character array of values to assign to the AES State
        AESState(unsigned char* s_input);

        /// @brief This method gets the unsigned character at a given index
        /// @param index The index at which to get the unsigned character
        /// @return The byte that is at the index
        unsigned char getByte(int index) const;

        /// @brief This method performs the multiplication of a byte within galois field 2**8
        /// @param byte_to_multiply The byte which is being multiplied
        /// @param mult_factor The factor by which the byte is being multiplied
        /// @return The result of the multiplication of the byte by the factor in the galois field 2**8
        static unsigned char xTimes(unsigned char byte_to_multiply, int mult_factor);

        /// @brief The method converts column and row numbers into a single index i
        /// @param c The column number
        /// @param r The row number
        /// @param max_c The maximum number of columns in the matrix (default 4)
        /// @return The index of the item at the given column and row
        static int cr2i(int c, int r, int max_c = 4);

        /// @brief This method performs the mix columns function from Figure 4 "Illustration of MIXCOLUMNS()" of Nist Fips 197
        void mixColumns();

        /// @brief This method performs the inverse mix columns function from Figure 4 "Illustration of MIXCOLUMNS()" of Nist Fips 197
        void invMixColumns();

        /// @brief This method prints the state as a 4x4 matrix to the console
        void printState() const;

        /// @brief This method substitutes bytes according to the substitution matrix from Figure 2 in NIST FIPS 197  "Illustration of SUBBYTES()"
        void subBytes();

        /// @brief This method substitutes bytes according to the inverse substitution matrix from Section 5.3.2 "INVSUBBYTES()" of NIST FIPS 197
        void invSubBytes();

        /// @brief This method performs the shift rows function as defined in NIST FIPS 197 section 5.1.2 "SHIFTROWS()"
        void shiftRows();

        /// @brief This method performs the inverse shift rows function as defined in NIST FIPS 197 section 5.3.1 "INVSHIFTROWS()"
        void invShiftRows();

        /// @brief This method performs the add round key function as defined in NIST FIPS 197 Section 5.1.4 "ADDROUNDKEY()"
        /// @param round_key 
        void addRoundKey(std::array<AESWord, 4> round_key);

        /// @brief The function takes the modulus of a value in case the value is negative
        /// @param value the value that we are taking the modulus of
        /// @param modulo the modulus
        /// @return The modulus value that is calculated
        static unsigned char mod(unsigned char value, unsigned char modulo);

        /// @brief This method overrides the == operator for AESState objects
        /// @param other The other word that is being compared
        /// @return A boolean that is true if all the bytes are the same
        bool operator==(const AESState &other) const;
};

#endif

