#ifndef AES_HPP
#define AES_HPP

#include "AESConstants.hpp"
#include "AESState.hpp"
#include "AESWord.hpp"
#include "AESKey.hpp"
#include "AESDataBlock.hpp"

#include <vector>
#include <cstdio>

/// @brief This class should include the cypher and most of the necessary components for Advanced Encryption Standard
/// as laid out in nist fips 197 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
class AES{
    protected :
        
        /// @brief This method transforms the input into a state array based on Section 3.4 "The State" of NIST FIPS 197
        /// @param input The input as an unsigned char array
        /// @return The corresponding state 
        static AESState input2State(unsigned char *input);

        /// @brief This method transforms the input into a state array based on Section 3.4 "The State" of NIST FIPS 197
        /// @param input The input as an AESDataBlock
        /// @return The corresponding state 
        static AESState input2State(const AESDataBlock &input);

        /// @brief This method transforms the state array into an output array based on Section 3.4 "The State" of NIST FIPS 197
        /// @param s The AESState
        /// @return The corresponding output
        static AESDataBlock state2Output(AESState s);

        /// @brief This method gets the 4 words which make up the subkey for this round
        /// @param round The round that the subkey is being retrieved for
        /// @param w The expanded key
        /// @return The subkey for the round
        static std::array<AESWord, 4> getRoundSubkey(int round, std::vector<AESWord> w);

        /// @brief This method performs the cypher operation on an input block as described in Section 5.1 "CIPHER()" from NIST FIPS 197
        /// @param input The input block
        /// @param Nr The number of rounds to perform
        /// @param w The expanded key
        /// @return The state following the cypher
        static AESState cypher(AESDataBlock, int Nr,  std::vector<AESWord> w);

        /// @brief This method performs the cypher operation on an input block as described in Section 5.2 "INVCIPHER()" from NIST FIPS 197
        /// @param input The input block (cypher text)
        /// @param Nr The number of rounds to perform
        /// @param w The expanded key
        /// @return The state following the inverse cypher
        static AESState invCypher(AESDataBlock input, int Nr, std::vector<AESWord> w);

    public:

        /// @brief This method perform the cypher for AES128
        /// @param input The input to the cypher
        /// @param key The key for the cypher
        /// @return The cypher text produced
        static AESDataBlock AES128Cypher(AESDataBlock input, unsigned char *key);

        /// @brief This method perform the cypher for AES192
        /// @param input The input to the cypher
        /// @param key The key for the cypher
        /// @return The cypher text produced
        static AESDataBlock AES192Cypher(AESDataBlock input, unsigned char *key);

        /// @brief This method perform the cypher for AES256
        /// @param input The input to the cypher
        /// @param key The key for the cypher
        /// @return The cypher text produced
        static AESDataBlock AES256Cypher(AESDataBlock input, unsigned char *key);

        /// @brief This method perform the cypher for AES128
        /// @param input The input to the cypher
        /// @param key The key for the cypher
        /// @return The cypher text produced
        static AESDataBlock AES128Cypher(AESDataBlock input, std::vector<AESWord> expanded_key);

        /// @brief This method perform the cypher for AES192
        /// @param input The input to the cypher
        /// @param key The key for the cypher
        /// @return The cypher text produced
        static AESDataBlock AES192Cypher(AESDataBlock input, std::vector<AESWord> expanded_key);

        /// @brief This method perform the cypher for AES256
        /// @param input The input to the cypher
        /// @param key The key for the cypher
        /// @return The cypher text produced
        static AESDataBlock AES256Cypher(AESDataBlock input, std::vector<AESWord> expanded_key);

        /// @brief This method perform the inverse cypher for AES128
        /// @param input The input to the inverse cypher
        /// @param key The key for the inverse cypher
        /// @return The plain text produced
        static AESDataBlock AES128InvCypher(AESDataBlock input, unsigned char *key);

        /// @brief This method perform the inverse cypher for AES192
        /// @param input The input to the inverse cypher
        /// @param key The key for the inverse cypher
        /// @return The plain text produced
        static AESDataBlock AES192InvCypher(AESDataBlock input, unsigned char *key);

        /// @brief This method perform the inverse cypher for AES256
        /// @param input The input to the inverse cypher
        /// @param key The key for the inverse cypher
        /// @return The plain text produced
        static AESDataBlock AES256InvCypher(AESDataBlock input, unsigned char *key);

        /// @brief This method perform the inverse cypher for AES128
        /// @param input The input to the inverse cypher
        /// @param key The key for the inverse cypher
        /// @return The plain text produced
        static AESDataBlock AES128InvCypher(AESDataBlock input, std::vector<AESWord> expanded_key);

        /// @brief This method perform the inverse cypher for AES192
        /// @param input The input to the inverse cypher
        /// @param key The key for the inverse cypher
        /// @return The plain text produced
        static AESDataBlock AES192InvCypher(AESDataBlock input, std::vector<AESWord> expanded_key);

        /// @brief This method perform the inverse cypher for AES256
        /// @param input The input to the inverse cypher
        /// @param key The key for the inverse cypher
        /// @return The plain text produced
        static AESDataBlock AES256InvCypher(AESDataBlock input, std::vector<AESWord> expanded_key);
};

#endif