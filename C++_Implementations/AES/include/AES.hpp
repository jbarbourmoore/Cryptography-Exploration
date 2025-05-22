/// @brief This class should include the cypher and most of the necessary components for Advanced Encryption Standard
/// as laid out in nist fips 197 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
class AES{
    private :
        // The array of values for substitution from NIST FIPS 197 : Table 4. "SBOX(): substitution values for the byte xy (in hexadecimal format)"
        static const unsigned char SBOX[16][16];

        // The array of values for inverse substitution from NIST FIPS 197 : Table 6. "INVSBOX(): substitution values for the byte xy (in hexadecimal format)"
        static const unsigned char INVSBOX[16][16];

        
};