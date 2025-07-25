#ifndef SHA_32bit_HPP
#define SHA_32bit_HPP

#include <SHA.hpp>

namespace sha32bit
{
    /// @brief A single 32 bit word for use in the SHA hashing algorithm
    typedef u_int32_t word;
    /// @brief 16 blocks of the 32 bit words for use in the SHA hashing algorithm
    typedef array<word, 16> block;
    /// @brief The list of blocks in the message
    typedef vector<block> message;
} // namespace sha32bit

using namespace std;
using namespace sha32bit;

/// @brief This class contains the data and functions necessary for SHA1 as defined in NIST FIPS 180-4
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
class SHA_32bit : public SHA {
    protected :
        /// @brief This method performs a right rotate on a given word
        /// @param input The word that is to be rotated to the right
        /// @param shift The number of bits that the word is to be rotated
        /// @return The result of the rotation to the right
        word ROTR(word input, int shift);

        /// @brief This method performs a left rotate on a given word
        /// @param input The word that is to be rotated to the left
        /// @param shift The number of bits that the word is to be rotated
        /// @return The result of the rotation to the left
        word ROTL(word input, int shift);

        /// @brief This method transforms a character array of 8 hex digits into a word
        /// @param input The string of 8 or fewer hex digits
        /// @return The value as a word
        word hexStringToWord(string input);

        /// @brief This method converts a word into a hexadecimal string
        /// @param input The word to be converted into a hex string
        /// @return The string of 8 hexadecimal character that have the value of the word
        string wordToHexString(word input);

        /// @brief This method implements ch as defined in section 4.1.1 "SHA-1 Functions" of NIST FIPS 180.4
        /// @param x The word parameter listed as 'x'
        /// @param y The word parameter listed as 'y'
        /// @param z The word parameter listed as 'y'
        /// @return the word which is the result of ch
        word ch(word x, word y, word z);

        // /// @brief This method implements parity as defined in section 4.1.1 "SHA-1 Functions" of NIST FIPS 180.4
        // /// @param x The word parameter listed as 'x'
        // /// @param y The word parameter listed as 'y'
        // /// @param z The word parameter listed as 'y'
        // /// @return the word which is the result of parity
        // word parity(word x, word y, word z);

        /// @brief This method implements maj as defined in section 4.1.1 "SHA-1 Functions" of NIST FIPS 180.4
        /// @param x The word parameter listed as 'x'
        /// @param y The word parameter listed as 'y'
        /// @param z The word parameter listed as 'y'
        /// @return the word which is the result of maj
        word maj(word x, word y, word z);

        /// @brief This method creates a string of the message as hex
        /// @param input The message
        /// @return a string of hex representing the message
        string messageToHexString(message input);

        /// @brief This method pads a string input
        /// @param input The string of the input with unknown length
        /// @return The message as a padded vector of blocks
        message padStringToMessage(string input);

        /// @brief This method pads a hex string input
        /// @param input The hex string of the input with unknown length
        /// @return The message as a padded vector of blocks
        message padHexStringToMessage(string input_hex);

        /// @brief This method finds the modulus value 
        /// @param value the value that we are taking the modulus of
        /// @param modulo the modulus
        /// @return The modulus value that is calculated
        u_int64_t mod(u_int64_t value, u_int64_t modulo);

    
};

/// @brief This class contains the data and functions necessary for SHA1 as defined in NIST FIPS 180-4
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
class SHA1 : public SHA_32bit {

    private :
 
        /// @brief The hash algorithm's message digest size in bits (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        static const int MESSAGE_DIGEST_SIZE = 160;

        /// @brief The constants used in SHA-1 as listed in section 4.2.1 "SHA-1 Constants" of NIST FIPS 180-4
        static const word K[4];

        /// @brief The starting hash values used in SHA-1 as listed in section 5.3.1 "SHA-1" of NIST FIPS 180-4
        static const word H0[5];

    public :

        /// @brief This method implements parity as defined in section 4.1.1 "SHA-1 Functions" of NIST FIPS 180.4
        /// @param x The word parameter listed as 'x'
        /// @param y The word parameter listed as 'y'
        /// @param z The word parameter listed as 'y'
        /// @return the word which is the result of parity
        word parity(word x, word y, word z);

        /// @brief This method hashes a message and output it as a hex string
        /// @param input the pre padded message to be hashed
        /// @return The hash digest as a hex string
        string hashMessageToHex(message input);

        string hashString(string input_string) override;

        string hashHexString(string input_hex) override;
};


class SHA256 : public SHA_32bit {
    protected :
        /// @brief The hash algorithm's message digest size in bits (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        const int MESSAGE_DIGEST_SIZE = 256;

        /// @brief The constants used in SHA-224 and SHA256 as listed in section 4.2.2 "SHA-224 and SHA-256 Constants" of NIST FIPS 180-4
        static const word K[64];

        /// @brief The starting hash values used in SHA-256 as listed in section 5.3.3 "SHA-256" of NIST FIPS 180-4
        static const word H0_SHA256[8];

        /// @brief The number of times to iterate over a single message block
        const int ITERATION_COUNT = 64;

        /// @brief This method returns the initial hash value for use with SHA256
        /// @return The constant word at that index
        virtual word getH0(int index);

        /// @brief This method returns the initial hash value for use with SHA256
        /// @return The constant word at that index
        virtual word getDigestSize();

        /// @brief The method performs the function as defined in section 4.1.2 SHA-224 and SHA-256 Functions of NIST-FIPS 180-4
        /// Epsilon 0-256 (x) = ROTR 2(x) xor ROTR 13(x) xor ROTR 22(x) 
        /// @param x The word which is being processed
        /// @return The word that is the result of the function
        word bigEpsilonFromZero(word x);

        /// @brief The method performs the function as defined in section 4.1.2 SHA-224 and SHA-256 Functions of NIST-FIPS 180-4
        /// Epsilon 1-256 (x) = ROTR 6(x) xor ROTR 11(x) xor ROTR 25(x) 
        /// @param x The word which is being processed
        /// @return The word that is the result of the function
        word bigEpsilonFromOne(word x);

        /// @brief The method performs the function as defined in section 4.1.2 SHA-224 and SHA-256 Functions of NIST-FIPS 180-4
        /// epsilon 0-256 (x) = ROTR 7(x) xor ROTR 18(x) xor SHR 3(x) 
        /// @param x The word which is being processed
        /// @return The word that is the result of the function
        word smallEpsilonFromZero(word x);

        /// @brief The method performs the function as defined in section 4.1.2 SHA-224 and SHA-256 Functions of NIST-FIPS 180-4
        /// epsilon 1-256 (x) = ROTR 17(x) xor ROTR 19(x) xor SHR 10(x) 
        /// @param x The word which is being processed
        /// @return The word that is the result of the function
        word smallEpsilonFromOne(word x);

        /// @brief This method hashes a message and output it as a hex string
        /// @param input the pre padded message to be hashed
        /// @return The hash digest as a hex string
        string hashMessageToHex(message input);

    public :
        /// @brief This method creates a SHA Hash Digest of the input string
        /// @param input_hex The string that is to be hashed
        /// @return The hex string of the hash digest
        string hashString(string input_string) override;

        /// @brief This method creates a SHA Hash Digest of the input hex string
        /// @param input_hex The hex string that is to be hashed
        /// @return The hex string of the hash digest
        string hashHexString(string input_hex) override;
};

class SHA224 : public SHA256 {
    protected :
        /// @brief The hash algorithm's message digest size in bits (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        const int MESSAGE_DIGEST_SIZE = 224;

        /// @brief The starting hash values used in SHA-224 as listed in section 5.3.4 "SHA-224" of NIST FIPS 180-4
        static const word H0_SHA224[8];

        /// @brief This method returns the initial hash value for use with SHA224
        /// @return The constant word at that index
        word getH0(int index) override;

        /// @brief This method returns the digest size for use with SHA224
        /// @return The constant word at that index
        word getDigestSize() override;

};

#endif