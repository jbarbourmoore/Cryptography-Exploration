#ifndef AESConstants_HPP
#define AESConstants_HPP

class AESConstants{

    public :
        /// @brief The array of values for the round constants from NIST FIPS 197 Table 5. "Round constants"
        static const unsigned char RCON[10][4];

        /// @brief The array of values for substitution from NIST FIPS 197 : Table 4. "SBOX(): substitution values for the byte xy (in hexadecimal format)"
        static const unsigned char SBOX[256];

        /// @brief The array of values for inverse substitution from NIST FIPS 197 : Table 6. "INVSBOX(): substitution values for the byte xy (in hexadecimal format)"
        static const unsigned char INVSBOX[256];

        /// @brief The array of values for the mix columns constants from NIST FIPS 197 Section 5.1.3 "MixColumns()"
        static const unsigned char MIXCOLS[16];

        /// @brief The array of values for the inverse mix columns constants from NIST FIPS 197 Section 5.3.3 "InvMixColumns()"
        static const unsigned char INVMIXCOLS[16];
};

#endif
