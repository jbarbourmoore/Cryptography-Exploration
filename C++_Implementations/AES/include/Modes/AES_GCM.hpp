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
        AESDataBlock GHASH(AESDataBlock H, std::vector<AESDataBlock> X);

        void GTCR();

};

#endif