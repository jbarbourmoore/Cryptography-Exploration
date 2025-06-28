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
        int w = 64;

        std::array<std::array<std::bitset<64>, 5>, 5> s;

    public :
        std::bitset<1600> getValueAsBitset();

        std::string getValueAsHex();

        static SHA3_State getStateFromHex(std::string hex_input);

        static SHA3_State getStateFromBitset(std::bitset<1600> bitset_input);

};

#endif