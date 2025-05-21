#ifndef RSAPrivateKey_HPP
#define RSAPrivateKey_HPP

#include <stddef.h>
#include <openssl/bn.h>

/// @brief This class contains the variables and methods for an RSA Private Key
class RSAPrivateKey{

    private:
        /// @brief The RSA Private Key modulus
        BIGNUM *n_ {NULL};

        /// @brief The RSA Private Key exponent
        BIGNUM *d_ {NULL};

        /// @brief the key length in bits
        int keylength_ {2048};

        /// @brief whether the private key is using the quintuple form
        bool quint_form_ {false};

        /// @brief The first large prime for the RSA key 
        BIGNUM *p_ {NULL};

        /// @brief The second large prime for the RSA key
        BIGNUM *q_ {NULL};

        /// @brief The private exponent mod p (d % p)
        BIGNUM *dP_ {NULL};

        /// @brief The private exponent mod 'q' (d % q)
        BIGNUM *dQ_ {NULL};

        /// @brief The modular inverse of 'p' in 'q' (p % q)
        BIGNUM *qInv_ {NULL};

        /// @brief The BN CTX to be used in the calculations for this private key
        BN_CTX *context_ = BN_CTX_new();

    public:
        /// @brief The initializer for an RSA public key with standard form
        /// @param n The private key 'n' value as a BIGNUM
        /// @param d The private key 'd' value as a BIGNUM
        /// @param key_length optional - the key length in bits, default is 2048
        RSAPrivateKey(BIGNUM *n, BIGNUM *d, int key_length = 2048);

        /// @brief The initializer for an RSA public key with quint form
        /// @param n The private key 'n' value as a BIGNUM
        /// @param d The private key 'd' value as a BIGNUM
        /// @param p The private key 'p' value as a BIGNUM
        /// @param q The private key 'q' value as a BIGNUM
        /// @param key_length optional - the key length in bits, default is 2048
        RSAPrivateKey(BIGNUM *n, BIGNUM *d, BIGNUM *p, BIGNUM *q, int key_length = 2048);

        /// @brief The initializer for an empty private key
        /// @param key_length optional - the key length in bits, default is 2048
        RSAPrivateKey(int key_length = 2048);

        /// @brief This method creates the RSA Private key from character arrays in decimal form
        /// @param charArrayN The character array for 'n' in decimal form
        /// @param charArrayD The character array for 'd' in decimal form
        /// @param keylength The int value for the key length in bits, default is 2048
        void fromDecCharArray(const char *charArrayN, const char *charArrayD, int keylength = 2048);

        /// @brief This method creates the RSA Private key from character arrays in hexadecimal form
        /// @param charArrayN The character array for 'n' in hexadecimal form
        /// @param charArrayD The character array for 'd' in decimal form
        /// @param keylength The int value for the key length in bits, default is 2048
        void fromHexCharArray(const char *charArrayN, const char *charArrayD, int keylength = 2048);

        /// @brief This method creates the RSA Private key from character arrays in decimal form using the quintuple form
        /// @param charArrayN The character array for 'n' in decimal form
        /// @param charArrayD The character array for 'd' in decimal form
        /// @param charArrayP The character array for 'p' in decimal form
        /// @param charArrayQ The character array for 'q' in decimal form
        /// @param keylength The int value for the key length in bits, default is 2048
        void fromDecCharArray_QuintForm(const char *charArrayN, const char *charArrayD, const char *charArrayP, const char *charArrayQ, int keylength = 2048);

        /// @brief This method creates the RSA Private key from character arrays in hexadecimal form using the quintuple form
        /// @param charArrayN The character array for 'n' in hexadecimal form
        /// @param charArrayD The character array for 'd' in hexadecimal form
        /// @param charArrayP The character array for 'p' in hexadecimal form
        /// @param charArrayQ The character array for 'q' in hexadecimal form
        /// @param keylength The int value for the key length in bits, default is 2048
        void fromHexCharArray_QuintForm(const char *charArrayN, const char *charArrayD, const char *charArrayP, const char *charArrayQ, int keylength = 2048);

        /// @brief This method calculates dP, dQ and qInv to be used with the quintuple form of the private key
        void populateQuintForm();

        /// @brief This method implement the decryption primitive as laid out in IETF RFC 8017 Section 5.1.2 "RSADP"
        /// @param charArrayCypherText The cypher text representative to be decrypted as a hexadecimal character array
        /// @return The decrypted plain text as a hexadecimal character array
        char* decryptionPrimitive(char const *charArrayCypherText);

        /// @brief This method simply says whether the private key is using the quintuple form
        /// @return a bool true if it is using the quintuple form
        bool isQuintForm();

        /// @brief This method returns the hexadecimal character array for the private key's 'n' value
        /// @return Hexadecimal character array for 'n' value
        char* getHexN();

        /// @brief This method returns the hexadecimal character array for the private key's 'd' value
        /// @return Hexadecimal character array for 'd' value
        char* getHexD();

        /// @brief This method returns the hexadecimal character array for the private key's 'd' value
        /// @return Hexadecimal character array for 'd' value
        char* getHexP();

        /// @brief This method returns the hexadecimal character array for the private key's 'd' value
        /// @return Hexadecimal character array for 'd' value
        char* getHexQ();

        /// @brief This method returns the hexadecimal character array for the private key's 'd' value
        /// @return Hexadecimal character array for 'd' value
        char* getHexdP();

        /// @brief This method returns the hexadecimal character array for the private key's 'd' value
        /// @return Hexadecimal character array for 'd' value
        char* getHexdQ();

        /// @brief This method returns the hexadecimal character array for the private key's 'd' value
        /// @return Hexadecimal character array for 'd' value
        char* getHexqInv();

        /// @brief This method returns the key length as a number of bits
        /// @return The int value of bits in the key length (nlen)
        int getKeyLength();

        /// @brief This method prints the details of the private key to the console
        void printKey();

        /// @brief This method frees the BIGNUM variables that were used in this instance of the private key
        void freeKey();

};

#endif