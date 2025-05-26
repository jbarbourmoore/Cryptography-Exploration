#ifndef AES_GCM_HPP
#define AES_GCM_HPP

#include "AES.hpp"

/// @brief This class contains the functions for AES in Galois / Counter Mode as defined in NIST SP 800 -38d
/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
class AES_GCM{

    public:

        void GHASH();

        void GTCR();

};

#endif