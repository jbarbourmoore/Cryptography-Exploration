#include "AES.hpp"

AESState AES::input2State(unsigned char *input){
    unsigned char temp[16];
    for (int r = 0; r < 4; r++){
        for (int c = 0; c < 4; c++){
            temp[AESState::cr2i(c, r)] = input[r + 4 * c];
        }
    }
    return AESState(temp);
}

void AES::state2Output(AESState s, unsigned char *result){
    for (int r = 0; r < 4; r++){
        for (int c = 0; c < 4; c++){
            result[r + 4 * c] = s.getByte(AESState::cr2i(c, r));
        }
    }
}