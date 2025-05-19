#include <sys/types.h>
#include <bits/stdc++.h>
#include <cassert>
#include <string.h>
#include <array>
#include <vector>
#include <ranges>

using namespace std;

/// @brief A single 32 bit word for use in the SHA hashing algorithm
typedef u_int32_t word;
/// @brief 16 blocks of the 32 bit words for use in the SHA hashing algorithm
typedef array<word, 16> block;
/// @brief The list of blocks in the message
typedef vector<block> message;

/// @brief This class contains the data and functions necessary for SHA1 as defined in NIST FIPS 180-4
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
class SHA1 {

    private :
        /// @brief The hash algorithm's block size in bits (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        static const int BLOCK_SIZE = 512;

        /// @brief The hash algorithm's word size in bits (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        static const int WORD_SIZE = 32;

        /// @brief The hash algorithm's message digest size in bits (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        static const int MESSAGE_DIGEST_SIZE = 160;

        /// @brief The hash algorithm's maximum message size in bits, that is the size < 2 ** var (src: NIST FIPS 180-4 Figure 1: Secure Hash Algorithm Properties)
        static const int MAX_MESSAGE_SIZE_POWER_OF_2 = 64;

        /// @brief The number of bits available in the final block
        static const int FINAL_BLOCK_CAPACITY = 448;

        /// @brief The constants used in the SHA-1 as list in section 4.2.1 "SHA-1 Constants" of NIST FIPS 180-4
        static const string K[4];

    public :

        /// @brief This method performs a right rotate on a given word
        /// @param input The word that is to be rotated to the right
        /// @param shift The number of bits that the word is to be rotated
        /// @return The result of the rotation to the right
        static word ROTR(word input, int shift);

        /// @brief This method performs a left rotate on a given word
        /// @param input The word that is to be rotated to the left
        /// @param shift The number of bits that the word is to be rotated
        /// @return The result of the rotation to the left
        static word ROTL(word input, int shift);

        /// @brief This method transforms a character array of 8 hex digits into a word
        /// @param input The string of 8 or fewer hex digits
        /// @return The value as a word
        static word hexStringToWord(string input);

        /// @brief This method converts a word into a hexadecimal string
        /// @param input The word to be converted into a hex string
        /// @return The string of 8 hexadecimal character that have the value of the word
        static string wordToHexString(word input);

        /// @brief This method implements ch as defined in section 4.1.1 "SHA-1 Functions" of NIST FIPS 180.4
        /// @param x The word parameter listed as 'x'
        /// @param y The word parameter listed as 'y'
        /// @param z The word parameter listed as 'y'
        /// @return the word which is the result of ch
        static word ch(word x, word y, word z);

        /// @brief This method implements parity as defined in section 4.1.1 "SHA-1 Functions" of NIST FIPS 180.4
        /// @param x The word parameter listed as 'x'
        /// @param y The word parameter listed as 'y'
        /// @param z The word parameter listed as 'y'
        /// @return the word which is the result of parity
        static word parity(word x, word y, word z);

        /// @brief This method implements maj as defined in section 4.1.1 "SHA-1 Functions" of NIST FIPS 180.4
        /// @param x The word parameter listed as 'x'
        /// @param y The word parameter listed as 'y'
        /// @param z The word parameter listed as 'y'
        /// @return the word which is the result of maj
        static word maj(word x, word y, word z);

        /// @brief This method pads a bit string input
        /// @param input The bit string of the input with unknown length
        /// @return The message as a padded vector of blocks
        static message padVectorBoolInput(vector<bool> input);

        /// @brief This method creates a string of the message as hex
        /// @param input The message
        /// @return a string of hex representing the message
        static string messageToHexString(message input);
};