/// @brief This class should include the cypher and most of the necessary components for Advanced Encryption Standard
/// as laid out in nist fips 197 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
class AES{
    protected :
        /// @brief The array of values for substitution from NIST FIPS 197 : Table 4. "SBOX(): substitution values for the byte xy (in hexadecimal format)"
        static const unsigned char SBOX[256];

        /// @brief The array of values for inverse substitution from NIST FIPS 197 : Table 6. "INVSBOX(): substitution values for the byte xy (in hexadecimal format)"
        static const unsigned char INVSBOX[256];

        /// @brief The array of values for the round constants from NIST FIPS 197 Table 5. "Round constants"
        static const unsigned char RNDCONST[10][4];

        /// @brief The array of values for the mix columns constants from NIST FIPS 197 Section 5.1.3 "MixColumns()"
        static const unsigned char MIXCOLS[16];

        /// @brief The array of values for the inverse mix columns constants from NIST FIPS 197 Section 5.3.3 "InvMixColumns()"
        static const unsigned char INVMIXCOLS[16];

        /// @brief This method performs the multiplication of a byte within galois field 2**8
        /// @param byte_to_multiply The byte which is being multiplied
        /// @param mult_factor The factor by which the byte is being multiplied
        /// @return The result of the multiplication of the byte by the factor in the galois field 2**8
        static unsigned char xTimes(unsigned char byte_to_multiply, int mult_factor);
};