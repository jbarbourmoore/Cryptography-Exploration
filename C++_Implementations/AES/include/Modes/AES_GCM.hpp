#ifndef AES_GCM_HPP
#define AES_GCM_HPP

#include "AES.hpp"
#include "inttypes.h"


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

        /// @brief This method handles the AES cipher for use in the gcm implementation
        /// @param input The input to the cipher as a single AESDataBlock
        /// @param key_type The key type (128, 192 or 256 bit)
        /// @param expanded_key The key for the AES in its expanded form
        /// @return The AESDataBlock that is the cipher text corresponding to the input
        AESDataBlock cipher(AESDataBlock input, AESKeyTypes key_type, std::vector<AESWord> expanded_key);

        /// @brief This method performs the authenticated encryption as laid out in Nist SP 800-38D Algorithm 4: "GCM-AEK (IV, P, A)"
        /// @param P The plain text as a hex string that is to be encrypted
        /// @param key_type The key type (128, 192, or 256 bit)
        /// @param K The key as a hex string
        /// @param t The (approved) tag length
        /// @param IV The initialization vector
        /// @param A Additional authentication data when applicable
        /// @return The hex string of the cipher text correspdoning to the input
        std::string authenticatedEncryption(std::string P, AESKeyTypes key_type, std::string K, int t, std::string IV, std::string A);

        void authenticatedDecryption();

        /// @brief This method returns an unsigned 64 bit integer as a hexadecimal string with 16 characters
        /// @param input The unsigned 64 bit integer
        /// @return The value as a hexadecimal string
        std::string getInt64AsString(u_int64_t input);

        /// @brief This method calculates the positive modulus of a given value
        /// @param input The input value
        /// @param modulus The modulus field to be calculating within
        /// @return The modulus value (positive)
        u_int64_t mod(u_int64_t input, int modulus);
};

#endif