#include "SHA1.hpp"

class SHA256 : public SHA1 {
    private :
        /// @brief The hash algorithm's message digest size in bits (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        static const int MESSAGE_DIGEST_SIZE = 160;

    public : 

        /// @brief The method performs the function as defined in section 4.1.2 SHA-224 and SHA-256 Functions of NIST-FIPS 180-4
        /// Epsilon 0-256 (x) = ROTR 2(x) xor ROTR 13(x) xor ROTR 22(x) 
        /// @param x The word which is being processed
        /// @return The word that is the result of the function
        static word bigEpsilonFromZero(word x);

        /// @brief The method performs the function as defined in section 4.1.2 SHA-224 and SHA-256 Functions of NIST-FIPS 180-4
        /// Epsilon 1-256 (x) = ROTR 6(x) xor ROTR 11(x) xor ROTR 25(x) 
        /// @param x The word which is being processed
        /// @return The word that is the result of the function
        static word bigEpsilonFromOne(word x);

        /// @brief The method performs the function as defined in section 4.1.2 SHA-224 and SHA-256 Functions of NIST-FIPS 180-4
        /// epsilon 0-256 (x) = ROTR 7(x) xor ROTR 18(x) xor SHR 3(x) 
        /// @param x The word which is being processed
        /// @return The word that is the result of the function
        static word smallEpsilonFromZero(word x);

        /// @brief The method performs the function as defined in section 4.1.2 SHA-224 and SHA-256 Functions of NIST-FIPS 180-4
        /// epsilon 1-256 (x) = ROTR 17(x) xor ROTR 19(x) xor SHR 10(x) 
        /// @param x The word which is being processed
        /// @return The word that is the result of the function
        static word smallEpsilonFromOne(word x);

};