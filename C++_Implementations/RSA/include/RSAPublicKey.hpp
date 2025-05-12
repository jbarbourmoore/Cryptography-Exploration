#ifndef RSAPublicKey_HPP
#define RSAPublicKey_HPP
#include <openssl/bn.h>
#include <string.h>

/// @brief This class contains the variables and methods for an RSA Public Key
class RSAPublicKey
{
    private:

        /// @brief The RSA Public Key modulus
        BIGNUM *n_ {BN_new()};

        /// @brief The RSA Public Key exponent
        BIGNUM *e_ {BN_new()};

        /// @brief the key length in bits
        int keylength_ {2048};

        /// @brief The BN CTX to be used in the calculations for this public key
        BN_CTX *context_ = BN_CTX_new();

    public: 

        /// @brief This method creates the RSA Public Key from character arrays in decimal form
        /// @param charArrayN The character array for 'n' in decimal form
        /// @param charArrayE The character array for 'e' in decimal form
        /// @param keylength The int value for the key length in bits, default is 2048
        void fromDecCharArray(const char *charArrayN, const char *charArrayE, int keylength = 2048);

        /// @brief This method creates the RSA Public Key from character arrays in hexadecimal form
        /// @param charArrayN The character array for 'n' in hexadecimal form
        /// @param charArrayE The character array for 'e' in hexadecimal form
        /// @param keylength The int value for the key length in bits, default is 2048
        void fromHexCharArray(const char *charArrayN, const char *charArrayE, int keylength = 2048);

        /// @brief This method prints the details of the public key to the console
        void printKey();

        /// @brief This method frees the BIGNUM variables that were used in this instance of the private key
        void freeKey();

        /// @brief This method returns the hexadecimal character array for the public key's 'n' value
        /// @return Hexadecimal character array for 'n' value
        char* getHexN();

        /// @brief This method returns the hexadecimal character array for the public key's 'e' value
        /// @return Hexadecimal character array for 'e' value
        char* getHexE();

        /// @brief This method returns the key length as a number of bits
        /// @return The int value of bits in the key length (nlen)
        int getKeyLength();

        /// @brief This method implement the encryption primitive as laid out in IETF RFC 8017 Section 5.1.1 "RSAEP"
        /// @param charArrayMessage The message plain text representative to be encrypted as a hexadecimal character array
        /// @return The encrypted message as a hexadecimal character array
        char* encryptionPrimitive(char const *charArrayMessage);

};

#endif