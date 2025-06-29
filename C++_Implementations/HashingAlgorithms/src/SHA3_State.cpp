#include "SHA3.hpp"

SHA3_State::SHA3_State(){
    a_ = std::array<std::array<std::bitset<64>, 5>, 5>();
}

SHA3_State::SHA3_State(std::bitset<1600> bitset_input){
    a_ = std::array<std::array<std::bitset<64>, 5>, 5>();
    for (int x = 0; x < 5; x ++){
        for (int y = 0; y < 5; y ++){
            for(int z = 0; z < w_; z ++){
                if(bitset_input.test(w_ * (5 * y + x) + z)){
                    setBit(true, x, y, z);
                }
            }
        }
    }
}

void SHA3_State::setBit(bool value, int x, int y, int z){
    a_.at(x).at(y).set(z, value);
}

bool SHA3_State::checkBit(int x, int y, int z){
    return a_.at(x).at(y).test(z);
}

void SHA3_State::printBits(){
    for (int x = 0; x < 5; x ++){
        for (int y = 0; y < 5; y ++){
            for(int z = 0; z < w_; z ++){
                printf("%d", checkBit(x, y, z));
            }
            printf(" ");
        }
        printf("\n");
    }
}

void SHA3_State::printHex(){
    printf("%s\n", getValueAsHex().c_str());
}

std::bitset<1600> SHA3_State::getValueAsBitset(){
    std::bitset<1600> result = std::bitset<1600>();
    for (int x = 0; x < 5; x ++){
        for (int y = 0; y < 5; y ++){
            for(int z = 0; z < w_; z ++){
                if (checkBit(x, y, z)){
                    setBit(true, x, y, z);
                    result.set(w_ * (5 * y + x) + z, true);
                }
            }
        }
    }
    return result;
}

std::string SHA3_State::getValueAsHex(){

    ///Algorithm 11: b2h(S) from NIST FIPS 202

    std::string res = "";
    std::bitset<1600> bits = getValueAsBitset();
    std::string hex_values = "0123456789ABCDEF";
    int m = 1600 / 8;
    for (int i = 0; i < m; i ++){
            int index = i * 8;
            int value = 0;
            for (int bit_position = 0; bit_position < 8; bit_position++){
                value += bits.test(index + bit_position) * pow(2, 7 - bit_position);
            }
            int remainder = value % 16;
            int divisor = (value - remainder) / 16;
            res.push_back(hex_values.at(divisor));
            res.push_back(hex_values.at(remainder));
    }
    return res;
}