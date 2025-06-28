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