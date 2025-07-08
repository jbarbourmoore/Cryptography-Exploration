#include "SHA3.hpp"

std::vector<std::bitset<1600>> SHA3::padBitMessage(std::vector<bool> bit_message, int digest_length){

    int c = 2 * digest_length;
    int x = block_bit_size_ - c;
    int input_bit_length = bit_message.size();
    int j = SHA3_State::mod(-1 * input_bit_length - 2, x);
    bit_message.push_back(true);
    for (int i = 0 ; i < j ; i ++){
        bit_message.push_back(false);
    }
    bit_message.push_back(true);

    int block_count = bit_message.size() / x;

    std::vector<std::bitset<1600>> result = vector<std::bitset<1600>>();

    for ( int block = 0 ; block < block_count ; block ++){
        result.push_back(std::bitset<1600>());
        for (int bit = 0 ; bit < x ; bit ++){
            result.at(block).set(bit, bit_message.at(block * x + bit));
        }
    }

    return result;
}

std::bitset<1600> SHA3::keccakF1600(std::bitset<1600> input_bits){
    // as defined in Algorithm 7: KECCAK-p[b, nr](S) and Section 3.4 keccak f of NIST FIPS 202
    SHA3_State state = SHA3_State(input_bits);

    for (int i = 0 ; i < 24 ; i ++){
        state.round(i);
    }

    return state.getValueAsBitset();
}

std::vector<bool> SHA3::sponge(std::vector<std::bitset<1600>> P, int digest_length){
    // as defined in Algorithm 8: SPONGE[f, pad, r](N, d) of NIST FIPS 202
    int n = P.size();
    std::bitset<1600> S = std::bitset<1600>();
    for(int i = 0 ; i < n ; i ++){
        S = S ^ P.at(i);
        S = keccakF1600(S);
    }
    std::vector<bool> Z = std::vector<bool>(digest_length);
    for (int i = 0 ; i < digest_length ; i ++){
        Z.at(i) = S.test(i);
    }
    return Z;
}

std::bitset<1600> SHA3::sponge(std::vector<std::bitset<1600>> P){
    int n = P.size();
    std::bitset<1600> S = std::bitset<1600>();
    for(int i = 0 ; i < n ; i ++){
        S = S ^ P.at(i);
        S = keccakF1600(S);
    }
    return S;
}

std::vector<bool> SHA3::h2b(std::string hex_input){
    // Algorithm 10: h2b(H, n) from NIST FIPS 202

    int hex_length = hex_input.size();
    int bit_length = hex_length * 4;
    std::vector<bool> bits = std::vector<bool>(bit_length);
    
    std::string hex_values = "0123456789ABCDEF";

    for (int i = 0; i < hex_length; i += 2){
        int value = hex_values.find(hex_input.at(i));
        value *= 16;
        value += hex_values.find(hex_input.at(i + 1));

        for (int bit_location = 0 ; bit_location < 8 ; bit_location ++){
            if(value >= pow(2, 7 - bit_location)){
                bits.at((i / 2) * 8 + 7 - bit_location) = true;
                value -= pow(2, 7 - bit_location);
            }
        }
    }
    
    return bits;
}


std::vector<bool> SHA3::sponge(std::vector<std::bitset<1600>> P, int internal_digest_length, int digest_length){
    // as defined in Algorithm 8: SPONGE[f, pad, r](N, d) of NIST FIPS 202
    int n = P.size();
    int r = 1600 - (2 * internal_digest_length);
    std::bitset<1600> S = std::bitset<1600>();
    for(int i = 0 ; i < n ; i ++){
        S = S ^ P.at(i);
        S = keccakF1600(S);
    }
    std::vector<bool> Z = std::vector<bool>();
    while (Z.size() < digest_length){
        for (int i = 0 ; i < r ; i ++){
            Z.push_back(S.test(i));
        }
        S = keccakF1600(S);
    }
    Z = {Z.begin(), Z.begin() + digest_length};
    return Z;
}