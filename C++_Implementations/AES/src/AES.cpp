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

AESState AES::input2State(const AESDataBlock &input){
    unsigned char temp[16];
    for (int r = 0; r < 4; r++){
        for (int c = 0; c < 4; c++){
            temp[AESState::cr2i(c, r)] = input.getByte(r + 4 * c);
        }
    }
    return AESState(temp);
}

AESDataBlock AES::state2Output(AESState s){
    AESDataBlock result = AESDataBlock();
    for (int r = 0; r < 4; r++){
        for (int c = 0; c < 4; c++){
            result.setByte(r + 4 * c, s.getByte(AESState::cr2i(c, r)));
        }
    }
    return result;
}

AESState AES::cypher(AESDataBlock input, int Nr,  std::vector<AESWord> w){
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

AESState AES::invCypher(AESDataBlock input, int Nr, std::vector<AESWord> w){
    AESState state = input2State(input);
    std::array<AESWord, 4> wi = getRoundSubkey(Nr, w);
    state.addRoundKey(wi);
    for (int round = Nr - 1; round > 0; round--){
        state.invShiftRows();
        state.invSubBytes();
        wi = getRoundSubkey(round, w);
        state.addRoundKey(wi);
        state.invMixColumns();
    }
    state.invShiftRows();
    state.invSubBytes();
    wi = getRoundSubkey(0, w);
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

AESDataBlock AES::AES128Cypher(AESDataBlock input, unsigned char *key){
    std::vector<AESWord> w = AESKey::keyExpansion(key, AES_KEY_128);
    int Nr = AESKey::getNr(AES_KEY_128);
    AESState state = cypher(input, Nr, w);
    return state2Output(state);
}

AESDataBlock AES::AES192Cypher(AESDataBlock input, unsigned char *key){
    std::vector<AESWord> w = AESKey::keyExpansion(key, AES_KEY_192);
    int Nr = AESKey::getNr(AES_KEY_192);
    AESState state = cypher(input, Nr, w);
    return state2Output(state);
}

AESDataBlock AES::AES256Cypher(AESDataBlock input, unsigned char *key){
    std::vector<AESWord> w = AESKey::keyExpansion(key, AES_KEY_256);
    int Nr = AESKey::getNr(AES_KEY_256);
    AESState state = cypher(input, Nr, w);
    return state2Output(state);
}

AESDataBlock AES::AES128Cypher(AESDataBlock input, std::vector<AESWord> expanded_key){
    int Nr = AESKey::getNr(AES_KEY_128);
    AESState state = cypher(input, Nr, expanded_key);
    return state2Output(state);
}

AESDataBlock AES::AES192Cypher(AESDataBlock input, std::vector<AESWord> expanded_key){
    int Nr = AESKey::getNr(AES_KEY_192);
    AESState state = cypher(input, Nr, expanded_key);
    return state2Output(state);
}

AESDataBlock AES::AES256Cypher(AESDataBlock input, std::vector<AESWord> expanded_key){
    int Nr = AESKey::getNr(AES_KEY_256);
    AESState state = cypher(input, Nr, expanded_key);
    return state2Output(state);
}

AESDataBlock AES::AES128InvCypher(AESDataBlock input, unsigned char *key){
    std::vector<AESWord> w = AESKey::keyExpansion(key, AES_KEY_128);
    int Nr = AESKey::getNr(AES_KEY_128);
    AESState state = invCypher(input, Nr, w);
    return state2Output(state);
}

AESDataBlock AES::AES192InvCypher(AESDataBlock input, unsigned char *key){
    std::vector<AESWord> w = AESKey::keyExpansion(key, AES_KEY_192);
    int Nr = AESKey::getNr(AES_KEY_192);
    AESState state = invCypher(input, Nr, w);
    return state2Output(state);
}

AESDataBlock AES::AES256InvCypher(AESDataBlock input, unsigned char *key){
    std::vector<AESWord> w = AESKey::keyExpansion(key, AES_KEY_256);
    int Nr = AESKey::getNr(AES_KEY_256);
    AESState state = invCypher(input, Nr, w);
    return state2Output(state);
}

AESDataBlock AES::AES128InvCypher(AESDataBlock input, std::vector<AESWord> expanded_key){
    int Nr = AESKey::getNr(AES_KEY_128);
    AESState state = invCypher(input, Nr, expanded_key);
    return state2Output(state);
}

AESDataBlock AES::AES192InvCypher(AESDataBlock input, std::vector<AESWord> expanded_key){
    int Nr = AESKey::getNr(AES_KEY_192);
    AESState state = invCypher(input, Nr, expanded_key);
    return state2Output(state);
}

AESDataBlock AES::AES256InvCypher(AESDataBlock input, std::vector<AESWord> expanded_key){
    int Nr = AESKey::getNr(AES_KEY_256);
    AESState state = invCypher(input, Nr, expanded_key);
    return state2Output(state);
}