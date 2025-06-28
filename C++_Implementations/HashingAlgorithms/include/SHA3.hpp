#ifndef SHA3_HPP
#define SHA3_HPP

#include "SHA.hpp"
#include <array>
#include <bitset>
#include <string>

class SHA3 : public SHA{

};

class SHA3_State {

    private :
        int w_ = 64;

        std::array<std::array<std::bitset<64>, 5>, 5> a_;

    public :

        SHA3_State();

        SHA3_State(std::bitset<1600> bitset_input);

        void setBit(bool value, int x, int y, int z);

        bool checkBit(int x, int y, int z);

        void printBits();

        std::bitset<1600> getValueAsBitset();

        std::string getValueAsHex();

        static SHA3_State getStateFromHex(std::string hex_input);

        static SHA3_State getStateFromBitset(std::bitset<1600> bitset_input);

};

#endif