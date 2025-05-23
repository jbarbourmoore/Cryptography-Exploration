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

std::array<unsigned char, 16> AES::state2Output(AESState s){
    std::array<unsigned char, 16> result;
    for (int r = 0; r < 4; r++){
        for (int c = 0; c < 4; c++){
            result[r + 4 * c] = s.getByte(AESState::cr2i(c, r));
        }
    }
    return result;
}

AESState AES::cypher(unsigned char *input, int Nr,  std::vector<AESWord> w){
    AESState state = input2State(input);
    std::array<AESWord, 4> wi = getRoundSubkey(0, w);
    state.addRoundKey(wi);
    for (int round = 1; round < Nr; round ++){
        state.subBytes();
        state.shiftRows();
        state.mixColumns();
        wi = getRoundSubkey(round, w);
        state.addRoundKey(wi);
    }
    state.subBytes();
    state.shiftRows();
    wi = getRoundSubkey(Nr, w);
    state.addRoundKey(wi);
    return state;
}

std::array<AESWord, 4> AES::getRoundSubkey(int round, std::vector<AESWord> w){
    std::array<AESWord, 4> wi;
    for (int i = 0; i < 4; i ++){
        wi[i] = AESWord(w[4 * round + i]);
    }
    return wi;
}

std::array<unsigned char, 16> AES::AES128Cypher(unsigned char *input, unsigned char *key){
    std::vector<AESWord> w = AESKey::keyExpansion(key, AES_KEY_128);
    int Nr = AESKey::getNr(AES_KEY_128);
    AESState state = cypher(input, Nr, w);
    return state2Output(state);
}

std::array<unsigned char, 16> AES::AES192Cypher(unsigned char *input, unsigned char *key){
    std::vector<AESWord> w = AESKey::keyExpansion(key, AES_KEY_192);
    int Nr = AESKey::getNr(AES_KEY_192);
    AESState state = cypher(input, Nr, w);
    return state2Output(state);
}

std::array<unsigned char, 16> AES::AES256Cypher(unsigned char *input, unsigned char *key){
    std::vector<AESWord> w = AESKey::keyExpansion(key, AES_KEY_256);
    int Nr = AESKey::getNr(AES_KEY_256);
    AESState state = cypher(input, Nr, w);
    return state2Output(state);
}