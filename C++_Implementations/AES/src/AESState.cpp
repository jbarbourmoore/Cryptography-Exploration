#include "AESState.hpp"

unsigned char AESState::xTimes(unsigned char byte_to_multiply, int mult_factor){\
    unsigned char result = 0;
    if(mult_factor == 1){
        result = byte_to_multiply;
    }
    else if(mult_factor == 2){
        result = (byte_to_multiply << 1) & 0xff;
        if(byte_to_multiply >= 128){
            result = result ^ 0x1b;
        }
    }
    else if (mult_factor % 2 == 0){
        unsigned char x_time_res = xTimes(byte_to_multiply, mult_factor / 2);
        result = (x_time_res << 1) & 0xff;
        if(x_time_res >= 128){
            result = result ^ 0x1b;
        }
    }
    else {
        result = xTimes(byte_to_multiply, mult_factor - 1);
        result = result ^ byte_to_multiply;
    }
    return result;
}

int AESState::cr2i(int c, int r, int max_c){
    return r * max_c + c;
}

void AESState::mixColumns(){
    unsigned char temp[16];
    for (int r = 0; r < 4; r++){
        for (int c = 0; c < 4; c++){
            unsigned char mult1 = xTimes(s[cr2i(c, 0)], MIXCOLS[cr2i(0, r)]);
            unsigned char mult2 = xTimes(s[cr2i(c, 1)], MIXCOLS[cr2i(1, r)]);
            unsigned char mult3 = xTimes(s[cr2i(c, 2)], MIXCOLS[cr2i(2, r)]);
            unsigned char mult4 = xTimes(s[cr2i(c, 3)], MIXCOLS[cr2i(3, r)]);
            // printf("%.2x ^ %.2x ^ %.2x ^ %.2x\n", mult1,mult2, mult3, mult4);
            temp[cr2i(c, r)] = mult1 ^ mult2 ^ mult3 ^ mult4;
        }
    }
    for (int i = 0; i < 16; i++){
        s[i] = temp[i];
    }
}

void AESState::invMixColumns(){
    unsigned char temp[16];
    for (int r = 0; r < 4; r++){
        for (int c = 0; c < 4; c++){
            unsigned char mult1 = xTimes(s[cr2i(c, 0)], INVMIXCOLS[cr2i(0, r)]);
            unsigned char mult2 = xTimes(s[cr2i(c, 1)], INVMIXCOLS[cr2i(1, r)]);
            unsigned char mult3 = xTimes(s[cr2i(c, 2)], INVMIXCOLS[cr2i(2, r)]);
            unsigned char mult4 = xTimes(s[cr2i(c, 3)], INVMIXCOLS[cr2i(3, r)]);
            temp[cr2i(c, r)] = mult1 ^ mult2 ^ mult3 ^ mult4;
        }
    }
    for (int i = 0; i < 16; i++){
        s[i] = temp[i];
    }
}

void AESState::printState(){
    for(int r = 0; r < 4; r++){
        for(int c= 0; c < 4; c++){
            printf("%.2x ", s[cr2i(c, r)]);
        }
        printf("\n");
    }
}

void AESState::subBytes(){
    for (int i = 0; i < 16; i++){
        s[i] = SBOX[s[i]];
    }
}

void AESState::invSubBytes(){
    for (int i = 0; i < 16; i++){
        s[i] = INVSBOX[s[i]];
    }
}

void AESState::shiftRows(){
    unsigned char temp[16];
    for (int r = 0; r < 4; r++){
        for (int c = 0; c < 4; c++){
            temp[cr2i(c, r)] = s[cr2i((c + r) % 4, r)];
        }
    }
    for (int i = 0; i < 16; i++){
        s[i] = temp[i];
    }
}

void AESState::invShiftRows(){
    unsigned char temp[16];
    for (int r = 0; r < 4; r++){
        for (int c = 0; c < 4; c++){
            temp[cr2i(c, r)] = s[cr2i(mod(c - r, 4), r)];
        }
    }
    for (int i = 0; i < 16; i++){
        s[i] = temp[i];
    }
}

AESState::AESState(){
    for (int i = 0; i < 16; i ++){
        s[i] = 0;
    }
}

AESState::AESState(unsigned char *s_input){
    for (int i = 0; i < 16; i ++){
        s[i] = s_input[i];
    }
}

unsigned char AESState::getByte(int index){
    return s[index];
}

unsigned char AESState::mod(unsigned char value, unsigned char modulo){
    return (value % modulo + modulo) % modulo;
}