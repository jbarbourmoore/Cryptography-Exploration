#ifndef SHA3_HPP
#define SHA3_HPP

#include "SHA.hpp"
#include <array>
#include <bitset>
#include <string>
#include <cmath>

class SHA3 : public SHA{

};

class SHA3_State {

    private :
        int w_ = 64;

        void bitsetToState(std::bitset<1600> bits_input);

        int mod(int val, int modulus);

        std::array<std::array<std::bitset<64>, 5>, 5> a_;

    public :

        SHA3_State();

        SHA3_State(std::bitset<1600> bitset_input);

        SHA3_State(std::string hex_input);

        void setBit(bool value, int x, int y, int z);

        bool checkBit(int x, int y, int z);

        void printBits();

        void printHex();

        std::bitset<1600> getValueAsBitset();

        std::string getValueAsHex();

        std::bitset<5> getRow(int y, int z);

        void setRow(int y, int z, std::bitset<5> input_row);

        std::bitset<5> getColumn(int x, int z);

        void setColumn(int x, int z, std::bitset<5> input_column);

        std::bitset<64> getLane(int x, int y);

        void setLane(int x, int y, std::bitset<64> input_lane);

        void theta();

        void rho();

};

#endif