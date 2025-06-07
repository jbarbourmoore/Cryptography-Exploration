#ifndef AES_GCM_HPP
#define AES_GCM_HPP

#include "AES.hpp"
#include "inttypes.h"

struct GCM_EncyptionResult{
    std::string cipher_text_;
    std::string tag_;
    GCM_EncyptionResult(std::string cipher_text, std::string tag);
};

struct GCM_DecryptionResult{
    bool status_;
    std::string plain_text_;
    GCM_DecryptionResult(bool status = false, std::string plain_text = "");
};

/// @brief This class contains the functions for AES in Galois / Counter Mode as defined in NIST SP 800 -38d
/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
class AES_GCM{

    private:
        /// @brief This function performs GCTR as defined in Section 6.5 "GCTR Function"
        /// @param key_type The enum value for the bit length of the AES Key 
        /// @param key The key as a hex string
        /// @param ICB The initital counter block
        /// @param hex_input The input as a hex string
        /// @return The encrypted message as a hex string
        static std::string GTCR(AESKeyTypes key_type, std::vector<AESWord> expanded_key, AESDataBlock ICB, std::string hex_input);

        /// @brief This method handles the AES cipher for use in the gcm implementation
        /// @param input The input to the cipher as a single AESDataBlock
        /// @param key_type The key type (128, 192 or 256 bit)
        /// @param expanded_key The key for the AES in its expanded form
        /// @return The AESDataBlock that is the cipher text corresponding to the input
        static AESDataBlock cipher(AESDataBlock input, AESKeyTypes key_type, std::vector<AESWord> expanded_key);

        /// @brief This method returns an unsigned 64 bit integer as a hexadecimal string with 16 characters
        /// @param input The unsigned 64 bit integer
        /// @return The value as a hexadecimal string
        static std::string getInt64AsString(u_int64_t input);

        /// @brief This method calculates the positive modulus of a given value
        /// @param input The input value
        /// @param modulus The modulus field to be calculating within
        /// @return The modulus value (positive)
        static u_int64_t mod(u_int64_t input, int modulus);

        /// @brief This method calculates the value for J0 based on the IV
        /// @param expanded_key The expanded form of the key
        /// @param key_type The key type (128, 192, or 256 bit)
        /// @param IV The initialization vector
        /// @param H The value for H (AES cipher of 0)
        /// @return The AESDataBlock containing J0
        static AESDataBlock calculateJ0(std::vector<AESWord> expanded_key, AESKeyTypes key_type, std::string IV, AESDataBlock H);

        /// @brief This method calculated the tag for the Authenticated Encryption / Decryption
        /// @param C The cipher text as a hex string
        /// @param A Additional authentication data when applicable
        /// @param expanded_key The expanded form of the key
        /// @param key_type The key type (128, 192, or 256 bit)
        /// @param IV The initialization vector
        /// @param J0 The AESDataBlock containing J0
        /// @param H The value for H (AES cipher of 0)
        /// @return The tag as a hex string
        static std::string calculateTag(std::string C, std::string A, std::vector<AESWord> expanded_key, AESKeyTypes key_type, std::string IV, AESDataBlock J0, AESDataBlock H);

    public:

        /// @brief This method performs the GHASH algorithm as defined in section 6.4 "GHASH Function"
        /// @param H The hash subkey
        /// @param X The input data to the GHASH
        /// @return The AESDataBlock Y, that is the result of the GHASH
        static AESDataBlock GHASH(AESDataBlock H, std::vector<AESDataBlock> X);

        /// @brief This method performs the authenticated encryption as laid out in Nist SP 800-38D Algorithm 4: "GCM-AEK (IV, P, A)"
        /// @param P The plain text as a hex string that is to be encrypted
        /// @param key_type The key type (128, 192, or 256 bit)
        /// @param K The key as a hex string
        /// @param t The (approved) tag length
        /// @param IV The initialization vector
        /// @param A Additional authentication data when applicable
        /// @return The GCM_EncyptionResult containing a hex string of the cipher text correspdoning to the input and the tag
        static GCM_EncyptionResult authenticatedEncryption(std::string P, AESKeyTypes key_type, std::string key, int t, std::string IV, std::string A);

        /// @brief This method performs the authenticated decryption as laid out in Nist SP 800-38D Algorithm 5: "GCM-ADK (IV, C, A, T) " 
        /// @param C The cipher text as a hex string that is to be decrypted
        /// @param key_type The key type (128, 192 or 256 bit)
        /// @param key The key as a hex string
        /// @param tag The tag that is provided along with the cipher text
        /// @param t The (approved) tag length
        /// @param IV The initialization vector
        /// @param A Additional authentication data when applicable
        /// @return The GCMDecryptionResult containing whether it was a success and the hex string of the plain text 
        static GCM_DecryptionResult authenticatedDecryption(std::string C, AESKeyTypes key_type, std::string key, std::string tag, int t, std::string IV, std::string A);

        
};

#endif