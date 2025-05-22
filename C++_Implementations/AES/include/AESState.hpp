#ifndef AESState_HPP
#define AESState_HPP

#include <cstdio>

struct AESState{

    private :
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
        unsigned char getByte(int index);

        /// @brief The array of values for substitution from NIST FIPS 197 : Table 4. "SBOX(): substitution values for the byte xy (in hexadecimal format)"
        static const unsigned char SBOX[256];

        /// @brief The array of values for inverse substitution from NIST FIPS 197 : Table 6. "INVSBOX(): substitution values for the byte xy (in hexadecimal format)"
        static const unsigned char INVSBOX[256];

        /// @brief The array of values for the mix columns constants from NIST FIPS 197 Section 5.1.3 "MixColumns()"
        static const unsigned char MIXCOLS[16];

        /// @brief The array of values for the inverse mix columns constants from NIST FIPS 197 Section 5.3.3 "InvMixColumns()"
        static const unsigned char INVMIXCOLS[16];

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
        void printState();

        /// @brief This method substitutes bytes according to the substitution matrix from Figure 2 in NIST FIPS 197  "Illustration of SUBBYTES()"
        void subBytes();

        /// @brief This method substitutes bytes according to the inverse substitution matrix from Section 5.3.2 "INVSUBBYTES()" of NIST FIPS 197
        void invSubBytes();

        /// @brief This method performs the shift rows function as defined in NIST FIPS 197 section 5.1.2 "SHIFTROWS()"
        void shiftRows();

        /// @brief This method performs the inverse shift rows function as defined in NIST FIPS 197 section 5.3.1 "INVSHIFTROWS()"
        void invShiftRows();

        /// @brief The function takes the modulus of a value in case the value is negative
        /// @param value the value that we are taking the modulus of
        /// @param modulo the modulus
        /// @return The modulus value that is calculated
        static unsigned char mod(unsigned char value, unsigned char modulo);
};

#endif

