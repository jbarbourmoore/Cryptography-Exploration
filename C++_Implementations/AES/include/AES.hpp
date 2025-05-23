#ifndef AES_HPP
#define AES_HPP

#include "AESConstants.hpp"
#include "AESState.hpp"
#include "AESWord.hpp"
#include "AESKey.hpp"

#include <cstdio>

/// @brief This class should include the cypher and most of the necessary components for Advanced Encryption Standard
/// as laid out in nist fips 197 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
class AES{
    protected :
        

        /// @brief This method transforms the input into a state array based on Section 3.4 "The State" of NIST FIPS 197
        /// @param input The input as an unsigned char array
        /// @return The corresponding state 
        static AESState input2State(unsigned char *input);

        /// @brief This method transforms the state array into an output array based on Section 3.4 "The State" of NIST FIPS 197
        /// @param s The AESState
        /// @return The corresponding output
        static void state2Output(AESState s, unsigned char *result);
};

#endif