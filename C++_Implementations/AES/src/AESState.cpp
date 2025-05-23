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
            unsigned char mult1 = xTimes(s[cr2i(c, 0)], AESConstants::MIXCOLS[cr2i(0, r)]);
            unsigned char mult2 = xTimes(s[cr2i(c, 1)], AESConstants::MIXCOLS[cr2i(1, r)]);
            unsigned char mult3 = xTimes(s[cr2i(c, 2)], AESConstants::MIXCOLS[cr2i(2, r)]);
            unsigned char mult4 = xTimes(s[cr2i(c, 3)], AESConstants::MIXCOLS[cr2i(3, r)]);
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
            unsigned char mult1 = xTimes(s[cr2i(c, 0)], AESConstants::INVMIXCOLS[cr2i(0, r)]);
            unsigned char mult2 = xTimes(s[cr2i(c, 1)], AESConstants::INVMIXCOLS[cr2i(1, r)]);
            unsigned char mult3 = xTimes(s[cr2i(c, 2)], AESConstants::INVMIXCOLS[cr2i(2, r)]);
            unsigned char mult4 = xTimes(s[cr2i(c, 3)], AESConstants::INVMIXCOLS[cr2i(3, r)]);
            temp[cr2i(c, r)] = mult1 ^ mult2 ^ mult3 ^ mult4;
        }
    }
    for (int i = 0; i < 16; i++){
        s[i] = temp[i];
    }
}

void AESState::printState() const{
    for(int r = 0; r < 4; r++){
        for(int c= 0; c < 4; c++){
            printf("%.2x ", s[cr2i(c, r)]);
        }
        printf("\n");
    }
}

void AESState::subBytes(){
    for (int i = 0; i < 16; i++){
        s[i] = AESConstants::SBOX[s[i]];
    }
}

void AESState::invSubBytes(){
    for (int i = 0; i < 16; i++){
        s[i] = AESConstants::INVSBOX[s[i]];
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

void AESState::addRoundKey(std::array<AESWord, 4> round_key){
    for (int c = 0; c < 4; c++){
        AESWord temp = AESWord(s[cr2i(c , 0)], s[cr2i(c , 1)], s[cr2i(c , 2)], s[cr2i(c , 3)]);
        temp.xorWord(round_key.at(c));
        for (int r = 0; r < 4; r++){
            s[cr2i(c , r)] = temp.getByte(r);
        }
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

unsigned char AESState::getByte(int index) const{
    return s[index];
}

unsigned char AESState::mod(unsigned char value, unsigned char modulo){
    return (value % modulo + modulo) % modulo;
}

bool AESState::operator==(const AESState &other) const{
    bool is_equal = true;
    for (int i = 0; i < 16; i++){
        if (getByte(i) != other.getByte(i)){
            is_equal = false;
        }
    }
    return is_equal;
}