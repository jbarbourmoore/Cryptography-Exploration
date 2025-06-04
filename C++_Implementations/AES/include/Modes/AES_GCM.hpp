#ifndef AES_GCM_HPP
#define AES_GCM_HPP

#include "AES.hpp"

/// @brief This class contains the functions for AES in Galois / Counter Mode as defined in NIST SP 800 -38d
/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
class AES_GCM{

    public:

        /// @brief This method performs the GHASH algorithm as defined in section 6.4 "GHASH Function"
        /// @param H The hash subkey
        /// @param X The input data to the GHASH
        /// @return The AESDataBlock Y, that is the result of the GHASH
        static AESDataBlock GHASH(AESDataBlock H, std::vector<AESDataBlock> X);

        /// @brief This function performs GCTR as defined in Section 6.5 "GCTR Function"
        /// @param key_type The enum value for the bit length of the AES Key 
        /// @param key The key as a hex string
        /// @param ICB The initital counter block
        /// @param hex_input The input as a hex string
        /// @return The encrypted message as a hex string
        std::string GTCR(AESKeyTypes key_type, std::string key, AESDataBlock ICB, std::string hex_input);

        AESDataBlock cipher(AESDataBlock input, AESKeyTypes key_type, std::vector<AESWord> expanded_key);

};

#endif