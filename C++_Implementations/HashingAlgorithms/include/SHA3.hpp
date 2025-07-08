#ifndef SHA3_HPP
#define SHA3_HPP

#include "SHA.hpp"
#include <array>
#include <bitset>
#include <string>
#include <cmath>


/// @brief This class tracks the internal state arrays for use in SHA3 as defined in NIST FIPS 202
///@cite  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

class SHA3_State {

    private :
        /// @brief The w value (dimension of the z bit set)
        /// This is specific to SHA3, and does not extrapolate to the broader keccak family
        int w_ = 64;

        /// @brief This method converts a single bitset to a state consisting of a 5 x 5 x 64 bit array
        /// @param bits_input 
        void bitsetToState(std::bitset<1600> bits_input);

        /// @brief The state array 5 x 5 x 64 bits
        std::array<std::array<std::bitset<64>, 5>, 5> a_;

    public :
         /// @brief This method calculated the positive modulus value 
        /// @param val The value of which the modulus is being calculated
        /// @param modulus The modulus
        /// @return The modulus of the given value as an int
        static int mod(int val, int modulus);

        /// @brief This method initializes a SHA3 state with a value of 0
        SHA3_State();

        /// @brief This method initializes a SHA3 state from a single dimension bitset
        /// @param bitset_input The single dimension bitset to be converted into the state array
        SHA3_State(std::bitset<1600> bitset_input);

        /// @brief This method initializes a SHA3 state from a hexadecimal string
        /// @param hex_input The hexadecimal input converted into a SHA3_state object
        SHA3_State(std::string hex_input);

        /// @brief The method sets a single bit within the state array 
        /// @param value The value to set the bit 
        /// @param x The x coordinate of the bit to be set
        /// @param y The y coordinate of the bit to be set
        /// @param z The z coordinate of the bit to be set
        void setBit(bool value, int x, int y, int z);

        /// @brief This method checks the current value of a bit within the state array
        /// @param x The x coordinate of the bit to be set
        /// @param y The y coordinate of the bit to be set
        /// @param z The z coordinate of the bit to be set
        /// @return The current value of the bit
        bool checkBit(int x, int y, int z);

        /// @brief This method prints the bits of the state array to the console 
        void printBits();

        /// @brief This method prints the value of the state array to the console as hexadecimal
        void printHex();

        /// @brief This method gets the value of the state array as a single bitset
        /// @return The bitset corresponding to the value of the state array
        std::bitset<1600> getValueAsBitset();

        /// @brief This method gets the value of the state array as a hexadecimal string
        /// @return The hexadecimal string corresponding to the value of the state array
        std::string getValueAsHex();

        /// @brief This method gets a single row from the state array
        /// @param y The y coordinate of the row
        /// @param z The z coordinate of the row
        /// @return The row of x bits at the y and z coordinate
        std::bitset<5> getRow(int y, int z);

        /// @brief This method sets a single row from the state array
        /// @param y The y coordinate of the row
        /// @param z The z coordinate of the row
        /// @param input_row The new row of x bits at the y and z coordinate
        void setRow(int y, int z, std::bitset<5> input_row);

        /// @brief This method gets a single column from the state array
        /// @param x The x coordinate of the column
        /// @param z The z coordinate of the column
        /// @return The column of y bits at the x and z coordinate
        std::bitset<5> getColumn(int x, int z);

        /// @brief This method sets a single column from the state array
        /// @param z The z coordinate of the column
        /// @param z The z coordinate of the column
        /// @param input_column The new column of x bits at the x and z coordinate
        void setColumn(int x, int z, std::bitset<5> input_column);

        /// @brief This method gets a single lane from the state array
        /// @param x The x coordinate of the lane
        /// @param z The y coordinate of the lane
        /// @return The lane of z bits at the x and y coordinate
        std::bitset<64> getLane(int x, int y);

        /// @brief This method sets a single lane from the state array
        /// @param z The z coordinate of the lane
        /// @param z The y coordinate of the lane
        /// @param input_lane The new lane of z bits at the x and y coordinate
        void setLane(int x, int y, std::bitset<64> input_lane);

        /// @brief This method performs Algorithm 1: θ(A) from NIST FIPS 202
        /// @cite https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        void theta();

        /// @brief This method performs Algorithm 2: ρ(A) from NIST FIPS 202
        /// @cite https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        void rho();

        /// @brief This method performs Algorithm 3: π(A) from NIST FIPS 202
        /// @cite https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        void pi();

        /// @brief This method performs Algorithm 4: χ(A) from NIST FIPS 202
        /// @cite https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        void chi();

        /// @brief This method performs Algorithm 6: iota from NIST FIPS 202
        /// @cite https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        /// @param ir The number of rounds
        void iota(int ir);

        /// @brief This method perform Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir). as defined in Section 3.3 KECCAK-p[b, nr] of NIST FIPS 202
        /// @cite https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        /// @param ir 
        void round(int ir);
};

class SHA3 {

    protected :

        /// @brief the number of bits in each internal block to be processed
        static const int block_bit_size_ = 1600;

        /// @brief The number of hexadecimal charaters in each internal block to be processed
        static const int block_hex_size_ = 400;

        /// @brief This method pads a binary message and breaks it into appropriate blocks for internal processing
        /// @cite Algorithm 9: pad10*1(x, m) from NIST FIPS 202 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        /// @param bit_message The binary message to be hashed
        /// @return The list of all binary blocks to be processed
        static std::vector<std::bitset<1600>> padBitMessage(std::vector<bool> bit_message, int digest_length);

        /// @brief This method performs the internal keccak sponge for SHA3
        /// @param P The message to be hashed as a vectory of 1600 bit bitsets
        /// @param digest_length The length of the digest to be retrieved
        /// @return The vector of boolean values representing the hash digest
        static std::vector<bool> sponge(std::vector<std::bitset<1600>> P, int digest_length);

        /// @brief This method performs the internal keccak f 1600 for SHA3
        /// @cite KECCAK[c] = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600 – c] from NIST FIPS 202 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
        /// @param P The message to be hashed as a vectory of 1600 bit bitsets
        /// @param digest_length The length of the digest to be retrieved
        /// @return std::bitset<1600> containing the cresult of keccak
        static std::bitset<1600> keccakF1600(std::bitset<1600> input_bits);

        /// @brief This method performs the internal keccak sponge for SHA3
        /// @param P The message to be hashed as a vectory of 1600 bit bitsets
        /// @param digest_length The length of the digest to be retrieved
        /// @return The std::bitset<1600> of boolean values representing the hash digest
        static std::bitset<1600> sponge(std::vector<std::bitset<1600>> P);

        /// @brief This method performs the internal keccak sponge for SHA3
        /// @param P The message to be hashed as a vectory of 1600 bit bitsets
        /// @param internal_digest_length The internal digest length to be used(128 for SHAKE128 and 256 for SHAKE256)
        /// @param digest_length The length of the digest to be retrieved
        /// @return The vector of boolean values representing the hash digest
        static std::vector<bool> sponge(std::vector<std::bitset<1600>> P, int internal_digest_length, int digest_length);

        /// @brief This method converts hexadecimal to binary following Algorithm 10: h2b(H, n) from NIST FIPS 202
        /// @param input_hex The input hexadecimal value as a string
        /// @return The vector of booleans containing the binary representation of the hexadecimal string input
        static std::vector<bool> h2b(std::string input_hex);

        /// @brief This method converts binary to hexadecimal following Algorithm Algorithm 11: b2h(S) from NIST FIPS 202
        /// @param bits The input binary value as a vector of booleans
        /// @return The hexadecimal representation of the binary input as a string 
        static std::string b2h(std::vector<bool> bits);
};

class SHA3_224 : private SHA3 {
    private :
        static const int d_ = 224;

        static std::string b2h(std::bitset<d_> bits);

    public :
        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The bitset containing the SHA3 hash value
        static std::bitset<d_> hashAsBitset(std::vector<bool> bit_message);

        /// @brief The input as a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The bitset containing the SHA3 hash value
        static std::bitset<d_> hashAsBitset(std::string hex_input);

        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::vector<bool> bit_message);

        /// @brief The input as bits in a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::string hex_input);
};

class SHA3_256 : private SHA3 {
    private :
        static const int d_ = 256;

        static std::string b2h(std::bitset<d_> bits);

    public :
        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The bitset containing the SHA3 hash value
        static std::bitset<d_> hashAsBitset(std::vector<bool> bit_message);

        /// @brief The input as a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The bitset containing the SHA3 hash value
        static std::bitset<d_> hashAsBitset(std::string hex_input);

        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::vector<bool> bit_message);

        /// @brief The input as bits in a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::string hex_input);
};

class SHA3_384 : private SHA3 {
    private :
        static const int d_ = 384;

        static std::string b2h(std::bitset<d_> bits);

    public :
        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The bitset containing the SHA3 hash value
        static std::bitset<d_> hashAsBitset(std::vector<bool> bit_message);

        /// @brief The input as a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The bitset containing the SHA3 hash value
        static std::bitset<d_> hashAsBitset(std::string hex_input);

        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::vector<bool> bit_message);

        /// @brief The input as bits in a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::string hex_input);
};

class SHA3_512 : private SHA3 {
    private :
        static const int d_ = 512;

        static std::string b2h(std::bitset<d_> bits);

    public :
        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The bitset containing the SHA3 hash value
        static std::bitset<d_> hashAsBitset(std::vector<bool> bit_message);

        /// @brief The input as a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The bitset containing the SHA3 hash value
        static std::bitset<d_> hashAsBitset(std::string hex_input);

        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::vector<bool> bit_message);

        /// @brief The input as bits in a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::string hex_input);
};

class SHAKE128 : protected SHA3 {
    private :
        static const int d_ = 128;

    public :
        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The boolean vector containing the SHA3 hash value
        static std::vector<bool> hashAsBitset(std::vector<bool> bit_message, int digest_length);

        /// @brief The input as a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The boolean vector containing the SHA3 hash value
        static std::vector<bool> hashAsBitset(std::string hex_input, int digest_length);

        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::vector<bool> bit_message, int digest_length);

        /// @brief The input as bits in a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::string hex_input, int digest_length);
};

class SHAKE256 : private SHAKE128 {
    private :
        static const int d_ = 256;

    public :
        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The boolean vector containing the SHA3 hash value
        static std::vector<bool> hashAsBitset(std::vector<bool> bit_message, int digest_length);

        /// @brief The input as a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The boolean vector containing the SHA3 hash value
        static std::vector<bool> hashAsBitset(std::string hex_input, int digest_length);

        /// @brief The input as bits in a vector of booleans
        /// @param bit_message The message as bits
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::vector<bool> bit_message, int digest_length);

        /// @brief The input as bits in a string of hexadecimal
        /// @param bit_message The message as hex
        /// @return The hexadecimal value containing the SHA3 hash value
        static std::string hashAsHex(std::string hex_input, int digest_length);
};
#endif